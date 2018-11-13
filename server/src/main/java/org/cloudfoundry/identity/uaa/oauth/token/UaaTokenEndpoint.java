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

package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.advice.HttpMethodNotSupportedAdvice;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
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
     * In case of PKCE (code_verifier parameter present), the code parameter in request
     * is modified to be build up as "code" = "code" + " " + "code_verifier",
     * to make the code_verifier available in: UaaTokenStore.
     * @param tokenRequestParameters
     * 				Token request parameters for validation and merge.
     * @return tokenRequestParameters with merged code value if had code verifier and code parameters.
     * @throws OAuth2Exception 
     * 				Code verifier parameter validation errors.
     */
    protected Map<String, String> mergeAuthorizationCodeWithCodeVerifier(Map<String, String> tokenRequestParameters) throws OAuth2Exception{
        if (tokenRequestParameters.containsKey(PkceValidationService.CODE_VERIFIER) && tokenRequestParameters.containsKey("code")) {
        	String codeVerifier = tokenRequestParameters.get(PkceValidationService.CODE_VERIFIER);
        	if (!StringUtils.hasText(codeVerifier)) {
    			throw new OAuth2Exception("Code verifier parameter must not be empty if provided.");
    		}else if(!PkceValidationService.isCodeVerifierParameterValid(codeVerifier)) {
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
