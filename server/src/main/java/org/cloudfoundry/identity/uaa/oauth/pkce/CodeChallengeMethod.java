/********************************************************************
 * Copyright (C) 2018 Siemens AG
 *******************************************************************/
package org.cloudfoundry.identity.uaa.oauth.pkce;

/**
 * All code challenge method MUST implement this interface to be able to use it
 * in PKCE validation service.
 * 
 * @author Zoltan Maradics
 *
 */
public interface CodeChallengeMethod {

	/**
	 * Validate code verifier based on code challenge method with code challenge.
	 * code_challenge = code_challenge_method(code_verifier)
	 * 
	 * @param codeVerifier
	 *            Code verifier parameter form Token request.
	 * @param codeChallenge
	 *            Code challenge parameter from Authorize request.
	 * @return True if code verifier transformed with code challenge method match
	 *         with code challenge. False otherwise.
	 */
	public boolean isCodeVerifierValid(String codeVerifier, String codeChallenge);

	/**
	 * Getter for Code Challenge Method implementation unique Id.
	 * 
	 * @return Code Challenge Method unique Id
	 */
	public String getCodeChallengeMethodId();

}
