/*
 *******************************************************************
 * Copyright (C) 2018 Siemens AG
 *******************************************************************
 */
package org.cloudfoundry.identity.uaa.oauth.pkce.validators;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Zoltan Maradics
 *
 */
public class PlainCodeChallengeValidatorTest {
	
    private PlainCodeChallengeValidator plainCodeChallengeMethod;
	
	private final String matchParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private final String mismatchParameter = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	
	@Before
	public void createPlainCodeChallengeMethod() throws Exception {
		plainCodeChallengeMethod = new PlainCodeChallengeValidator();
	}
	
	@Test
	public void testCodeVerifierMethodWithMatchParameters() throws Exception {
		assertTrue(plainCodeChallengeMethod.isCodeVerifierValid(matchParameter, matchParameter));
	}
	
	@Test
	public void testCodeVerifierMethodWithMismatchParameters() throws Exception {
		assertFalse(plainCodeChallengeMethod.isCodeVerifierValid(matchParameter, mismatchParameter));
	}
	
	@Test
	public void testCodeChallengeIsNull() throws Exception {
		assertFalse(plainCodeChallengeMethod.isCodeVerifierValid(matchParameter, null));
	}
	
	@Test
	public void testCodeVerifierIsNull() throws Exception {
		assertFalse(plainCodeChallengeMethod.isCodeVerifierValid(null, matchParameter));
	}

}
