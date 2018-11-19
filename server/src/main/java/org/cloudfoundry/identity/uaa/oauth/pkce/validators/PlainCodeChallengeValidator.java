/*
 *******************************************************************
 * Copyright (C) 2018 Siemens AG
 *******************************************************************
 */
package org.cloudfoundry.identity.uaa.oauth.pkce.validators;

import org.cloudfoundry.identity.uaa.oauth.pkce.CodeChallengeValidator;
/**
 * Plain code challenge method implementation.
 * 
 * @author Zoltan Maradics
 *
 */
public class PlainCodeChallengeValidator implements CodeChallengeValidator{

	private final String codeChallengeMethod = "plain"; 
	
	@Override
	public boolean isCodeVerifierValid(String codeVerifier, String codeChallenge) {
		if (codeVerifier == null || codeChallenge == null) {
			return false;
		}
		return codeChallenge.contentEquals(codeVerifier);
	}

	@Override
	public String getCodeChallengeMethod() {
		return codeChallengeMethod;
	}
}
