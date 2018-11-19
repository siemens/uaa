/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
/*
 * ****************************************************************************
 *     Copyright (C) 2018 Siemens AG - PKCE related changes only.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.advice.HttpMethodNotSupportedAdvice;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.stereotype.Controller;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.springframework.util.StringUtils.hasText;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;


@Controller
@RequestMapping(value = "/oauth/token") //used simply because TokenEndpoint wont match /oauth/token/alias/saml-entity-id
public class UaaTokenEndpoint extends TokenEndpoint {

    private Boolean allowQueryString = null;

    public UaaTokenEndpoint() {
        setAllowedRequestMethods(new HashSet<>(Arrays.asList(HttpMethod.GET, HttpMethod.POST)));
    }

    public boolean isAllowQueryString() {
        return allowQueryString == null ? true : allowQueryString;
    }

    public void setAllowQueryString(boolean allowQueryString) {
        this.allowQueryString = allowQueryString;
        if (allowQueryString) {
            setAllowedRequestMethods(new HashSet<>(Arrays.asList(HttpMethod.GET, HttpMethod.POST)));
        } else {
            setAllowedRequestMethods(Collections.singleton(HttpMethod.POST));
        }
    }

    @RequestMapping(value = "**", method = GET)
    public ResponseEntity<OAuth2AccessToken> doDelegateGet(Principal principal,
                                                           @RequestParam Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
        return getAccessToken(principal, parameters);
    }

    @RequestMapping(value = "**", method = POST)
    public ResponseEntity<OAuth2AccessToken> doDelegatePost(Principal principal,
                                                            @RequestParam Map<String, String> parameters,
                                                            HttpServletRequest request) throws HttpRequestMethodNotSupportedException {
        if (hasText(request.getQueryString()) && !isAllowQueryString()) {
            logger.debug("Call to /oauth/token contains a query string. Aborting.");
            throw new HttpRequestMethodNotSupportedException("POST");
        }
        parameters = mergeAuthorizationCodeWithCodeVerifier(parameters);
        return postAccessToken(principal, parameters);
    }
    /**
     * In case the token request contains a code verifier (making use of PKCE),
     * the code verifier needs to be made available to UaaTokenStore,
     * which handles the validation of the code verifier
     * (by comparing it to the code challange provided in the authorization request).
     * 
     * As Spring Security OAuth libs do NOT support PKCE as of now, the following work around is implemented 
     * to make the code verifier available in the UaaTokenStore:
     * 
     * If token request contains a code_verifier (and a code), then the "code" parameter handed over to the Spring Security OAuth libs
     * is an artifical parameter made up as "code" + " " + "code_verifier" (using " " (blank) as separator). 
     * The UaaTokenStore was modified to deconstruct the artifical code parameter to "code" and "code_verifier" in case it contains a blank.
     * 
     * Assumptions: 
     *  - Code parameter is opaque to Spring Security OAuth libs on the way to hand over the parameter to UaaTokenStore; 
     *  - the real "code" does not contain blanks.
     * 
     * 
     * @param tokenRequestParameters
     * 				Token request parameters for validation and merge.
     * @return tokenRequestParameters with merged code value if had code verifier and code parameters.
     * @throws OAuth2Exception 
     * 				Code verifier parameter validation errors.
     */
    protected Map<String, String> mergeAuthorizationCodeWithCodeVerifier(Map<String, String> tokenRequestParameters) {
    	String code = tokenRequestParameters.get("code");
    	/* Need to check "code" parameter does not empty, otherwise it could 
		 * occurred to send "code_verifier" without "code" parameter and
		 * the response is "Invalid Authorization code" instead of "Missing code parameter"  
		 */
    	if(code == null || code.isEmpty()) {
    		return tokenRequestParameters;
    	}else if (tokenRequestParameters.get("code").contains(" ")) {
    		throw new OAuth2Exception("Unsupported Authorization Code: Contains blank character");
    	}
    	String codeVerifier = tokenRequestParameters.get(PkceValidationService.CODE_VERIFIER);
    	if (codeVerifier != null ) {
    		if(!PkceValidationService.isCodeVerifierParameterValid(codeVerifier)) {
    			throw new OAuth2Exception("Code verifier length must between 43 and 128 and use only [A-Z],[a-z],[0-9],_,.,-,~ characters.");
    		}
        	tokenRequestParameters.put("code", tokenRequestParameters.get("code")+" "+tokenRequestParameters.get(PkceValidationService.CODE_VERIFIER));
        }
        return tokenRequestParameters;
    }

    @RequestMapping(value = "**")
    public void methodsNotAllowed(HttpServletRequest request) throws HttpRequestMethodNotSupportedException {
        throw new HttpRequestMethodNotSupportedException(request.getMethod());
    }


    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    @Override
    public ResponseEntity<OAuth2Exception> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException e) throws Exception {
        return new HttpMethodNotSupportedAdvice().handleMethodNotSupportedException(e);
    }

    @ExceptionHandler(Exception.class)
    @Override
    public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
        logger.error("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage(), e);
        return getExceptionTranslator().translate(e);
    }

    @Override
    public void setAllowedRequestMethods(Set<HttpMethod> allowedRequestMethods) {
        if (isAllowQueryString()) {
            super.setAllowedRequestMethods(allowedRequestMethods);
        } else {
            super.setAllowedRequestMethods(Collections.singleton(HttpMethod.POST));
        }
    }
}
