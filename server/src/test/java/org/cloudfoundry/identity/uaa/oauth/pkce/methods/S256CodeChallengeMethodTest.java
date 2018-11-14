/********************************************************************
 * Copyright (C) 2018 Siemens AG
 *******************************************************************/
package org.cloudfoundry.identity.uaa.oauth.pkce.methods;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Zoltan Maradics
 *
 */
public class S256CodeChallengeMethodTest {
	
	private S256CodeChallengeMethod s256CodeChallengeMethod;
	
	private final String validCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private final String validCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	
	@Before
	public void createS256CodeChallengeMethod() throws Exception {
		s256CodeChallengeMethod = new S256CodeChallengeMethod();
	}
	
	@Test
	public void testCodeVerifierMethodWithMatchParameters() throws Exception {
		assertTrue(s256CodeChallengeMethod.isCodeVerifierValid(validCodeVerifier, validCodeChallenge));
	}
	
	@Test
	public void testCodeVerifierMethodWithMismatchParameters() throws Exception {
		assertFalse(s256CodeChallengeMethod.isCodeVerifierValid(validCodeVerifier, validCodeVerifier));
	}
	
	@Test
	public void testCodeChallengeIsNull() throws Exception {
		assertFalse(s256CodeChallengeMethod.isCodeVerifierValid(validCodeVerifier, null));
	}
	
	@Test
	public void testCodeVerifierIsNull() throws Exception {
		assertFalse(s256CodeChallengeMethod.isCodeVerifierValid(null, validCodeChallenge));
	}

}
