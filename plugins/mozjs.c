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
#include <sys/ioctl.h>
#include <pthread.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>

#pragma GCC diagnostic ignored "-Wredundant-decls"
#include <jsapi.h>
#pragma GCC diagnostic error "-Wredundant-decls"

#include "javascript.h"

#include "pacrunner.h"
#include "js.h"

static pthread_mutex_t mozjs_mutex = PTHREAD_MUTEX_INITIALIZER;

struct pacrunner_mozjs {
	struct pacrunner_proxy *proxy;
	JSContext *jsctx;
	JSObject *jsobj;
};

static int getaddr(const char *node, char *host, size_t hostlen)
{
	struct sockaddr_in addr;
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -EIO;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, node, sizeof(ifr.ifr_name));

	err = ioctl(sk, SIOCGIFADDR, &ifr);

	close(sk);

	if (err < 0)
		return -EIO;

	memcpy(&addr, &ifr.ifr_addr, sizeof(addr));
	snprintf(host, hostlen, "%s", inet_ntoa(addr.sin_addr));

	return 0;
}

static int resolve(const char *node, char *host, size_t hostlen)
{
	struct addrinfo *info;
	int err;

	if (getaddrinfo(node, NULL, NULL, &info) < 0)
		return -EIO;

	err = getnameinfo(info->ai_addr, info->ai_addrlen,
				host, hostlen, NULL, 0, NI_NUMERICHOST);

	freeaddrinfo(info);

	if (err < 0)
		return -EIO;

	return 0;
}

static JSBool myipaddress(JSContext *jsctx, uintN argc, jsval *vp)
{
	struct pacrunner_mozjs *ctx = JS_GetContextPrivate(jsctx);
	const char *interface;
	char address[NI_MAXHOST];

	DBG("");

	JS_SET_RVAL(jsctx, vp, JSVAL_NULL);

	if (!ctx)
		return JS_TRUE;

	interface = pacrunner_proxy_get_interface(ctx->proxy);
	if (!interface)
		return JS_TRUE;

	if (getaddr(interface, address, sizeof(address)) < 0)
		return JS_TRUE;

	DBG("address %s", address);

	JS_SET_RVAL(jsctx, vp, STRING_TO_JSVAL(JS_NewStringCopyZ(jsctx,
							       address)));

	return JS_TRUE;
}

static JSBool dnsresolve(JSContext *ctx, uintN argc, jsval *vp)
{
	char address[NI_MAXHOST];
	jsval *argv = JS_ARGV(ctx, vp);
	char *host = JS_EncodeString(ctx, JS_ValueToString(ctx, argv[0]));
	char **split_res;

	DBG("host %s", host);

	JS_SET_RVAL(ctx, vp, JSVAL_NULL);

	/* Q&D test on host to know if it is a proper hostname */
	split_res = g_strsplit_set(host, ":%?!,;@\\'*|<>{}[]()+=$&~# \"", -1);
	if (split_res) {
		int length = g_strv_length(split_res);
		g_strfreev(split_res);

		if (length > 1)
			goto out;
	}

	if (resolve(host, address, sizeof(address)) < 0)
		goto out;

	DBG("address %s", address);

	JS_SET_RVAL(ctx, vp, STRING_TO_JSVAL(JS_NewStringCopyZ(ctx, address)));

 out:
	JS_free(ctx, host);
	return JS_TRUE;

}

static JSClass jscls = {
	"global", JSCLASS_GLOBAL_FLAGS,
	JS_PropertyStub, JS_PropertyStub, JS_PropertyStub,
	JS_StrictPropertyStub,
	JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub, JS_FinalizeStub,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static JSRuntime *jsrun;

static int create_object(struct pacrunner_proxy *proxy)
{
	struct pacrunner_mozjs *ctx;
	const char *script;
	jsval rval;

	script = pacrunner_proxy_get_script(proxy);
	if (!script)
		return 0;

	ctx = g_malloc0(sizeof(struct pacrunner_mozjs));

	ctx->proxy = proxy;
	ctx->jsctx = JS_NewContext(jsrun, 8 * 1024);
	if (!ctx->jsctx) {
		g_free(ctx);
		return -ENOMEM;
	}
	JS_SetContextPrivate(ctx->jsctx, ctx);
	__pacrunner_proxy_set_jsctx(proxy, ctx);

#if JS_VERSION >= 185
	ctx->jsobj = JS_NewCompartmentAndGlobalObject(ctx->jsctx, &jscls,
						      NULL);
#else
	ctx->jsobj = JS_NewObject(ctx->jsctx, &jscls, NULL, NULL);
#endif

	if (!JS_InitStandardClasses(ctx->jsctx, ctx->jsobj))
		pacrunner_error("Failed to init JS standard classes");

	JS_DefineFunction(ctx->jsctx, ctx->jsobj, "myIpAddress",
			  myipaddress, 0, 0);
	JS_DefineFunction(ctx->jsctx, ctx->jsobj,
			  "dnsResolve", dnsresolve, 1, 0);

	JS_EvaluateScript(ctx->jsctx, ctx->jsobj, JAVASCRIPT_ROUTINES,
			  strlen(JAVASCRIPT_ROUTINES), NULL, 0, &rval);

	JS_EvaluateScript(ctx->jsctx, ctx->jsobj, script, strlen(script),
			  "wpad.dat", 0, &rval);

	return 0;
}

static int mozjs_clear_proxy(struct pacrunner_proxy *proxy)
{
	struct pacrunner_mozjs *ctx = __pacrunner_proxy_get_jsctx(proxy);

	DBG("proxy %p ctx %p", proxy, ctx);

	if (!ctx)
		return -EINVAL;

	JS_DestroyContext(ctx->jsctx);
	__pacrunner_proxy_set_jsctx(proxy, NULL);

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
	struct pacrunner_mozjs *ctx = __pacrunner_proxy_get_jsctx(proxy);
	JSBool result;
	jsval rval, args[2];
	char *answer, *g_answer;

	DBG("proxy %p ctx %p url %s host %s", proxy, ctx, url, host);

	if (!ctx)
		return NULL;

	pthread_mutex_lock(&mozjs_mutex);

	JS_BeginRequest(ctx->jsctx);

	args[0] = STRING_TO_JSVAL(JS_NewStringCopyZ(ctx->jsctx, url));
	args[1] = STRING_TO_JSVAL(JS_NewStringCopyZ(ctx->jsctx, host));

	result = JS_CallFunctionName(ctx->jsctx, ctx->jsobj,
				     "FindProxyForURL", 2, args, &rval);

	JS_EndRequest(ctx->jsctx);

	JS_MaybeGC(ctx->jsctx);

	pthread_mutex_unlock(&mozjs_mutex);

	if (result) {
		answer = JS_EncodeString(ctx->jsctx,
					 JS_ValueToString(ctx->jsctx, rval));
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

	jsrun = JS_NewRuntime(8 * 1024 * 1024);

	return pacrunner_js_driver_register(&mozjs_driver);
}

static void mozjs_exit(void)
{
	DBG("");

	pacrunner_js_driver_unregister(&mozjs_driver);

	JS_DestroyRuntime(jsrun);
}

PACRUNNER_PLUGIN_DEFINE(mozjs, mozjs_init, mozjs_exit)
