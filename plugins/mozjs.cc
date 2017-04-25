/*
 *
 *  PACrunner - Proxy configuration daemon
 *
 *  Copyright (C) 2010-2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include <netdb.h>

#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Winvalid-offsetof"
#include <jsapi.h>
#pragma GCC diagnostic error "-Wredundant-decls"
#pragma GCC diagnostic error "-Winvalid-offsetof"

extern "C" {
#include "pacrunner.h"
#include "js.h"
}

static pthread_mutex_t mozjs_mutex = PTHREAD_MUTEX_INITIALIZER;

struct pacrunner_mozjs {
	struct pacrunner_proxy *proxy;
	JSContext *jsctx;
	JSObject *jsobj;
	JSAutoCompartment *jsac;
};

static bool myipaddress(JSContext *jsctx, unsigned argc, jsval *vp)
{
	struct pacrunner_mozjs *ctx = (pacrunner_mozjs *)JS_GetContextPrivate(jsctx);
	char address[NI_MAXHOST];

	DBG("");

	JS::CallArgs args = JS::CallArgsFromVp(argc, vp);

	args.rval().setNull();

	if (!ctx)
		return true;

	if (__pacrunner_js_getipaddr(ctx->proxy, address, sizeof(address)) < 0)
		return true;

	DBG("address %s", address);

	args.rval().setString(JS_NewStringCopyZ(jsctx,address));

	return true;
}

static bool dnsresolve(JSContext *jsctx, unsigned argc, jsval *vp)
{
	struct pacrunner_mozjs *ctx = (pacrunner_mozjs *)JS_GetContextPrivate(jsctx);
	char address[NI_MAXHOST];
	JS::CallArgs args = JS::CallArgsFromVp(argc,vp);
	char * host = JS_EncodeString(jsctx, args[0].toString());

	DBG("host %s", host);

	if (!ctx)
		goto out;

	if (__pacrunner_js_resolve(ctx->proxy, host, address, sizeof(address)) < 0)
		goto out;

	DBG("address %s", address);

	args.rval().setString(JS_NewStringCopyZ(jsctx,address));

 out:
	JS_free(jsctx, host);
	return true;

}

static JSClass jscls = {
	"global", JSCLASS_GLOBAL_FLAGS,
};

static JSRuntime *jsrun;

static int create_object(struct pacrunner_proxy *proxy)
{
	struct pacrunner_mozjs *ctx;
	const char *script;

	script = pacrunner_proxy_get_script(proxy);
	if (!script)
		return 0;

	ctx = (pacrunner_mozjs *)g_malloc0(sizeof(struct pacrunner_mozjs));

	ctx->proxy = proxy;
	ctx->jsctx = JS_NewContext(jsrun, 8 * 1024);
	if (!ctx->jsctx) {
		g_free(ctx);
		return -ENOMEM;
	}
	JS_SetContextPrivate(ctx->jsctx, ctx);
	__pacrunner_proxy_set_jsctx(proxy, ctx);

	JS::CompartmentOptions compart_opts;
	compart_opts.setVersion(JSVERSION_LATEST);
	ctx->jsobj = JS_NewGlobalObject(ctx->jsctx, &jscls, nullptr,
					JS::DontFireOnNewGlobalHook, compart_opts);
	JS::RootedObject jsobj(ctx->jsctx,ctx->jsobj);

	ctx->jsac = new JSAutoCompartment(ctx->jsctx, jsobj);

	if (!JS_InitStandardClasses(ctx->jsctx, jsobj))
		pacrunner_error("Failed to init JS standard classes");

	JS_DefineFunction(ctx->jsctx, jsobj, "myIpAddress", myipaddress, 0, 0);
	JS_DefineFunction(ctx->jsctx, jsobj, "dnsResolve", dnsresolve, 1, 0);

	JS::RootedValue rval(ctx->jsctx);
	JS::CompileOptions opts(ctx->jsctx);
	opts.setIntroductionType("pacrunner")
	    .setUTF8(true)
	    .setCompileAndGo(true);

	JS::Evaluate(ctx->jsctx, JS::HandleObject(jsobj), opts,
		     __pacrunner_js_routines, strlen(__pacrunner_js_routines)
		     , &rval);

	JS::Evaluate(ctx->jsctx, jsobj, opts, script, strlen(script), &rval);

	return 0;
}

static int mozjs_clear_proxy(struct pacrunner_proxy *proxy)
{
	struct pacrunner_mozjs *ctx = (pacrunner_mozjs *)__pacrunner_proxy_get_jsctx(proxy);

	DBG("proxy %p ctx %p", proxy, ctx);

	if (!ctx)
		return -EINVAL;

	delete ctx->jsac;
	JS_DestroyContext(ctx->jsctx);
	__pacrunner_proxy_set_jsctx(proxy, NULL);
	g_free(ctx);

	return 0;
}

static int mozjs_set_proxy(struct pacrunner_proxy *proxy)
{
	DBG("proxy %p", proxy);
	if (!proxy)
		return 0;

	mozjs_clear_proxy(proxy);

	return create_object(proxy);
}

static char * mozjs_execute(struct pacrunner_proxy *proxy, const char *url,
			    const char *host)
{
	struct pacrunner_mozjs *ctx = (pacrunner_mozjs *)__pacrunner_proxy_get_jsctx(proxy);
	bool result;
	char *answer, *g_answer;
	DBG("proxy %p ctx %p url %s host %s", proxy, ctx, url, host);

	if (!ctx)
		return NULL;

	pthread_mutex_lock(&mozjs_mutex);

	JS_BeginRequest(ctx->jsctx);
	JS::RootedValue rval(ctx->jsctx);
	JS::AutoValueArray<2> args(ctx->jsctx);

	args[0].setString(JS_NewStringCopyZ(ctx->jsctx, url));
	args[1].setString(JS_NewStringCopyZ(ctx->jsctx, host));


	JS::RootedObject jsobj(ctx->jsctx,ctx->jsobj);

	result = JS_CallFunctionName(ctx->jsctx, jsobj, "FindProxyForURL", args , &rval);

	JS_EndRequest(ctx->jsctx);

	JS_MaybeGC(ctx->jsctx);

	pthread_mutex_unlock(&mozjs_mutex);

	if (result) {
		answer = JS_EncodeString(ctx->jsctx, rval.toString());
		g_answer = g_strdup(answer);
		JS_free(ctx->jsctx, answer);
		return g_answer;
	}

	return NULL;
}

static struct pacrunner_js_driver mozjs_driver = {
	.name		= "mozjs",
	.priority	= PACRUNNER_JS_PRIORITY_DEFAULT,
	.set_proxy	= mozjs_set_proxy,
	.clear_proxy	= mozjs_clear_proxy,
	.execute	= mozjs_execute,
};

static int mozjs_init(void)
{
	DBG("");
	JS_Init();
	jsrun = JS_NewRuntime(JS::DefaultHeapMaxBytes, 8 * 1024 * 1024 );

	return pacrunner_js_driver_register(&mozjs_driver);
}

static void mozjs_exit(void)
{
	DBG("");

	pacrunner_js_driver_unregister(&mozjs_driver);

	JS_DestroyRuntime(jsrun);
	JS_ShutDown();
}

PACRUNNER_PLUGIN_DEFINE(mozjs, mozjs_init, mozjs_exit)
