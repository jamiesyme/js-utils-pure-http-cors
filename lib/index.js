// References:
//
// - https://fetch.spec.whatwg.org/#http-cors-protocol
// - https://www.w3.org/TR/2020/SPSD-cors-20200602/
// - https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
// - https://github.com/rs/cors/blob/master/cors.go


// These options refuse everything by default. They're intended to serve as a
// conservative base to build a set of production options from.
//
export const paranoidCorsOptions = {
	isOriginAllowed       : () => false,
	isMethodAllowed       : () => false,
	isHeaderAllowed       : () => false,
	originWildcardEnabled : true,
	credentialsAllowed    : false,
	headersExposed        : [],
	maxAge                : 0,
}

// These options approve everything by default. They're EXTREMELY UNSAFE, and
// should only be used for quick development purposes.
//
// NOTE: you'll need to call `expandExposeHeadersWildcard()` after
// `handleCorsRequest()`.
//
export const permissiveCorsOptions = {
	isOriginAllowed       : origin => origin !== '*',
	isMethodAllowed       : () => true,
	isHeaderAllowed       : () => true,
	originWildcardEnabled : false,
	credentialsAllowed    : true,
	headersExposed        : ['*'],
	maxAge                : 86400, // 1 day
}

// These options are an opiniated set of restrictions that serve as reasonable
// secure default.
//
// NOTE: the origin wildcard is used by default; when allowing credentials,
// you'll also need to change `isOriginAllowed()` (see `permissiveCorsOptions`).
//
export const sensibleCorsOptions = {
	isOriginAllowed: () => true,
	isMethodAllowed (method)
	{
		// Based on "simple request methods" according to the spec.
		//
		// See: https://www.w3.org/TR/2020/SPSD-cors-20200602/#simple-method
		//
		return ['get', 'head', 'post'].includes(method.toLowerCase())
	},
	isHeaderAllowed (header)
	{
		// Based on CORS-safelisted request headers, plus "Origin" (why is
		// this not safelisted?).
		//
		// See: https://fetch.spec.whatwg.org/#cors-safelisted-request-header
		//
		return [
			'accept',
			'accept-language',
			'content-language',
			'content-type',
			'origin',
			'range',
		].includes(header)
	},
	credentialsAllowed: false,
	exposedHeaders: [],
	maxAge: 86400, // 1 day
}


function parseCsv (str)
{
	return str
		.split(',')
		.map(s => s.trim())
		.filter(Boolean)
}


export function isCorsRequest (request)
{
	return Boolean(request.headers.origin)
}

export function isCorsPreflightRequest (request)
{
	// I don't think "Access-Control-Request-Method" is required for CORS
	// preflight requests.
	//
	// From MDN:
	//
	//   "This header is required if the request has an
	//   Access-Control-Request-Headers header."
	//
	// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
	//
	return (
		isCorsRequest(request) &&
		request.method === 'OPTIONS' &&
		Boolean(request.headers['access-control-request-method'])
	)
}

export function createCorsRequestHandler (options)
{
	const {
		isOriginAllowed,
		isMethodAllowed,
		isHeaderAllowed,
		credentialsAllowed,
		exposedHeaders,
		maxAge,
	} = {
		...sensibleCorsOptions,
		...options,
	}

	function handleCorsRequest (request)
	{
		if (isCorsPreflightRequest(request)) {
			return handleCorsPreflightRequest(request)
		}

		function createResponse (headers = {})
		{
			// We should always set the "Vary" header, even if this isn't a CORS
			// request.
			//
			// See: https://github.com/rs/cors/issues/10
			//
			headers = {
				...headers,
				vary: 'origin',
			}

			return { headers }
		}

		if (!isCorsRequest(request)) {
			return createResponse()
		}

		// Non-preflighted CORS requests are approved based on their origin and
		// method.
		//
		// To refuse a non-preflight CORS request, we omit the necessary
		// approval headers.
		//
		const reqOrigin = request.headers.origin
		if (!reqOrigin) {
			return createResponse()
		}
		if (!isOriginAllowed(reqOrigin)) {
			return createResponse()
		}
		if (!isMethodAllowed(request.method)) {
			return createResponse()
		}

		// This looks like a valid request. Let's put together a response with
		// the required headers.
		//
		// According to MDN, clients treat wildcard origins specially
		// (disallowing their use with credentials), so we should be sure to
		// preserve that behavior.
		//
		// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
		//
		let headers = {
			'access-control-allow-origin': isOriginAllowed('*') ? '*' : reqOrigin,
		}
		if (credentialsAllowed) {
			headers['access-control-allow-credentials'] = 'true'
		}
		if (exposedHeaders.length > 0) {
			headers['access-control-expose-headers'] = exposedHeaders.join(', ')
		}

		return createResponse(headers)
	}

	function handleCorsPreflightRequest (request)
	{
		function createResponse (status, headers = {})
		{
			// We should always set the "Vary" header.
			//
			// See:
			//   https://github.com/rs/cors/issues/10
			//   https://github.com/rs/cors/commit/dbdca4d95feaa7511a46e6f1efb3b3aa505bc43f#commitcomment-12352001
			//
			headers = {
				...headers,
				vary: [
					'origin',
					'access-control-request-method',
					'access-control-request-headers',
				].join(', '),
			}

			return { status, headers }
		}

		// CORS preflight requests must use the "OPTIONS" method
		if (request.method !== 'OPTIONS') {
			return createResponse(400)
		}

		// CORS requests are approved based on their origin, method, and headers
		const reqOrigin = request.headers.origin
		if (!reqOrigin) {
			return createResponse(400)
		}
		if (!isOriginAllowed(reqOrigin)) {
			return createResponse(403)
		}

		const acrMethod = request.headers['access-control-request-method']
		if (!acrMethod) {
			return createResponse(400)
		}
		if (!isMethodAllowed(acrMethod)) {
			return createResponse(403)
		}

		const acrHeaders = request.headers['access-control-request-headers']
		if (acrHeaders) {
			for (const header of parseCsv(acrHeaders)) {
				if (!isHeaderAllowed(header)) {
					return createResponse(403)
				}
			}
		}

		// This looks like a valid preflight request. Let's put together a
		// response with the required headers.
		//
		// According to MDN, clients treat wildcard origins specially
		// (disallowing their use with credentials), so we should be sure to
		// preserve that behavior.
		//
		// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
		//
		let headers = {
			'access-control-allow-origin': isOriginAllowed('*') ? '*' : reqOrigin,
			'access-control-allow-methods': acrMethod,
		}
		if (acrHeaders) {
			headers['access-control-allow-headers'] = acrHeaders
		}
		if (credentialsAllowed) {
			headers['access-control-allow-credentials'] = 'true'
		}
		if (maxAge > 0) {
			headers['access-control-max-age'] = maxAge.toString()
		}

		return createResponse(204, headers)
	}

	return {
		handleCorsRequest,
		handleCorsPreflightRequest,
	}
}

export function expandExposeHeadersWildcard (headers)
{
	const acExposeHeaders = headers?.['access-control-expose-headers']
	if (acExposeHeaders) {

		const hasWildcard = parseCsv(acExposeHeaders).includes('*')
		if (hasWildcard) {

			const allHeaderNames = Object.keys(headers)
			headers = {
				...headers,
				'access-control-expose-headers': allHeaderNames.join(', '),
			}
		}
	}

	return headers
}
