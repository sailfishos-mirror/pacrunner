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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "pacrunner.h"

enum pacrunner_manual_exclude_appliance {
	PACRUNNER_MANUAL_EXCLUDE_POST = 0,
	PACRUNNER_MANUAL_EXCLUDE_PRE  = 1,
	PACRUNNER_MANUAL_EXCLUDE_ANY  = 2,
};

static int parse_uri(char *uri,
			char **host,
			char **protocol,
			gboolean no_path,
			gboolean exclusion)
{
	int ret = PACRUNNER_MANUAL_EXCLUDE_POST;
	gboolean proto, post_confirmed, ipv6;
	char *scheme, *sep, *cur;
	long int port;
	int length;

	proto = post_confirmed = ipv6 = FALSE;
	port = -1;

	/**
	 * Make sure host and protocol, if given, are properly set.
	 */
	if (host != NULL)
		*host = NULL;

	if (protocol != NULL)
		*protocol = NULL;

	/**
	 * The parsing will actually process on a copy of given uri
	 */
	scheme = g_strdup(uri);
	if (scheme == NULL)
		goto error;

	cur = scheme;

	/**
	 * 1 - parsing protocol first
	 * Note: protocol scheme is here totally ignored
	 */
	sep = strstr(cur, "://");
	if (sep != NULL) {
		if (sep == cur)
			goto error;

		if (protocol != NULL) {
			*sep = '\0';

			*protocol = g_strdup(cur);
			if (*protocol == NULL)
				goto error;
		}

		cur = sep + 3;
		proto = TRUE;
	}

	/**
	 * 2 - detecting end of uri
	 * Note: in case of server/exclusion configuration,
	 * no path should be present
	 */
	sep = strchr(cur, '/');
	if (sep != NULL) {
		if (exclusion == TRUE || (*(sep + 1) != '\0' &&
							no_path == TRUE))
			goto error;

		*sep = '\0';
	}

	/**
	 * 3 - We skip <login:password> if present
	 * Note: exclusion rule cannot contain such authentication information
	 */
	sep = strchr(cur, '@');
	if (sep != NULL) {
		if (exclusion == TRUE)
			goto error;

		*sep = '\0';
		cur = sep + 1;
	}

	/**
	 * 4 - Are we in front of a possible IPv6 address?
	 * Note: ipv6 format is not checked!
	 */
	sep = strchr(cur, '[');
	if (sep != NULL) {
		char *bracket;

		bracket = strchr(cur, ']');
		if (bracket == NULL)
			goto error;

		cur = sep;
		sep = strchr(bracket, ':');

		ipv6 = TRUE;
	} else
		sep = strchr(cur, ':');

	/**
	 * 5 - Checking port validity if present
	 * Note: exclusion rule cannot embed port
	 */
	if (sep != NULL) {
		char *err = NULL;

		if (exclusion == TRUE)
			goto error;

		errno = 0;
		port = strtol(sep+1, &err, 10);
		if (*err != '\0' || port <= 0 || port > USHRT_MAX ||
					errno == ERANGE || errno == EINVAL)
			goto error;

		*sep = '\0';
	}

	/**
	 * 6 - We detect/trim '.'/'*' from start
	 * Note: This is valid only for exclusion URI since it defines
	 * its rule's appliance */
	for (sep = cur; *sep != '\0' && (*sep == '*' || *sep == '.'); sep++)
		*sep = '\0';

	if (sep != cur) {
		if (exclusion == FALSE)
			goto error;

		cur = sep;
		post_confirmed = TRUE;
	}

	/**
	 * 7 - Parsing host if present
	 */
	length = strlen(cur);
	if (length > 0) {
		const char *forbidden_chars;
		char **forbidden = NULL;

		/**
		 * We first detect/trim '.'/'*' from end
		 * Note: valid only for exclusion
		 */
		for (sep = cur + length - 1;
			*sep != '\0' && (*sep == '*' || *sep == '.'); sep--)
			*sep = '\0';

		if (sep - cur + 1 != length) {
			if (exclusion == FALSE)
				goto error;

			length = sep - cur + 1;

			ret = PACRUNNER_MANUAL_EXCLUDE_PRE;
			if (post_confirmed == TRUE)
				ret = PACRUNNER_MANUAL_EXCLUDE_ANY;
		}

		if ((length > 255) || (*cur == '-' || *sep == '-') ||
				((*cur == '\0') && (exclusion == FALSE ||
				(exclusion == TRUE && proto == FALSE))))
			goto error;

		/**
		 * We do not allow some characters. However we do not run
		 * a strict check if it's an IP address which is given
		 */
		if (ipv6 == TRUE)
			forbidden_chars = "%?!,;@\\'*|<>{}()+=$&~# \"";
		else
			forbidden_chars = "%?!,;@\\'*|<>{}[]()+=$&~# \"";

		forbidden = g_strsplit_set(cur, forbidden_chars, -1);
		if (forbidden != NULL) {
			length = g_strv_length(forbidden);
			g_strfreev(forbidden);

			if (length > 1)
				goto error;
		}

		if (host != NULL && *cur != '\0') {
			if (port > 0) {
				/**
				 * Instead of transcoding the port back
				 * to string we just get the host:port line
				 * from the original uri.
				 * */
				cur = uri + (cur - scheme);

				sep = strchr(cur, '/');
				if (sep != NULL)
					length = sep - cur;
				else
					length = strlen(cur);

				*host = g_strndup(cur, length);
			} else
				*host = g_strdup(cur);

			if (*host == NULL)
				goto error;
		}
	} else {
		if (exclusion == FALSE ||
				(exclusion == TRUE && proto == FALSE))
			goto error;
		else
			ret = PACRUNNER_MANUAL_EXCLUDE_ANY;
	}

	g_free(scheme);

	return ret;

error:
	if (protocol != NULL) {
		g_free(*protocol);
		*protocol = NULL;
	}

	g_free(scheme);

	return -EINVAL;
}

GList **__pacrunner_manual_parse_servers(char **servers)
{
	char *host, *protocol;
	char **uri;
	int ret;

	if (servers == NULL)
		return NULL;

	for (uri = (char **)servers; *uri != NULL; uri++) {
		ret = parse_uri(*uri, &host, &protocol, TRUE, FALSE);

		if (ret < 0)
			continue;

		g_free(host);
		g_free(protocol);
	}

	return NULL;
}

void __pacrunner_manual_destroy_servers(GList **servers)
{
	return;
}

GList **__pacrunner_manual_parse_excludes(char **excludes)
{
	return NULL;
}

void __pacrunner_manual_destroy_excludes(GList **excludes)
{
	return;
}

char *__pacrunner_manual_execute(const char *url, const char *host,
				 GList **servers, GList **excludes)
{
	DBG("url %s host %s", url, host);

	if (servers == NULL || servers[0] == NULL)
		return NULL;

	return g_strdup_printf("PROXY %s", (char *)servers[0]->data);
}

int __pacrunner_manual_init(void)
{
	DBG("");

	return 0;
}

void __pacrunner_manual_cleanup(void)
{
	DBG("");
}
