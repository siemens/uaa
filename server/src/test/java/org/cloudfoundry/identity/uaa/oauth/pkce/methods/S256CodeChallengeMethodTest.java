package org.cloudfoundry.identity.uaa.oauth.pkce.methods;

import org.junit.Before;
import org.junit.Test;

public class S256CodeChallengeMethodTest {
	
	private S256CodeChallengeMethod s256CodeChallengeMethod;
	
	private final String validCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private final String validCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	
	@Before
	public void createS256CodeChallengeMethod() throws Exception {
		s256CodeChallengeMethod = new S256CodeChallengeMethod();
	}
	
	@Test
	public void testCodeChallengeMethodWithMatchParameters() throws Exception {
		s256CodeChallengeMethod.isCodeVerifierValid(validCodeVerifier, validCodeChallenge);
	}
	
	@Test
	public void testCodeChallengeMethodWithMismatchParameters() throws Exception {
		s256CodeChallengeMethod.isCodeVerifierValid(validCodeVerifier, validCodeVerifier);
	}

}
