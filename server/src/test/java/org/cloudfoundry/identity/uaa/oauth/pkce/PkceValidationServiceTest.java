/*
 *******************************************************************
 * Copyright (C) 2018 Siemens AG
 *******************************************************************
 */
package org.cloudfoundry.identity.uaa.oauth.pkce;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.hamcrest.Matchers.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.PlainPkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.S256PkceVerifier;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Zoltan Maradics
 *
 */
public class PkceValidationServiceTest {

	private PkceValidationService pkceValidationService;
	private Map<String, String> authorizeRequestParameters;

	private final String longCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cME9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cME9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private final String shortCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c";
	private final String containsForbiddenCharactersCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM%";
	private final String validPlainCodeChallengeOrCodeVerifierParameter1 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private final String validPlainCodeChallengeOrCodeVerifierParameter2 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	private final String invalidCodeChallengeMethod = "InvalidMethod";
	private final String plainCodeChallengeMethod = "plain";

	@Before
	public void createPkceValidationService() throws Exception {
		pkceValidationService = new PkceValidationService(createCodeChallengeValidators());
		authorizeRequestParameters = new HashMap<String, String>();
	}

	@Test
	public void testLongCodeChallengeParameter() throws Exception {
		assertFalse(PkceValidationService.matchWithPattern(longCodeChallengeOrCodeVerifierParameter));
	}

	@Test
	public void testShortCodeChallengeParameter() throws Exception {
		assertFalse(PkceValidationService.matchWithPattern(shortCodeChallengeOrCodeVerifierParameter));
	}

	@Test
	public void testContainsForbiddenCharactersCodeChallengeParameter() throws Exception {
		assertFalse(PkceValidationService
				.matchWithPattern(containsForbiddenCharactersCodeChallengeOrCodeVerifierParameter));
	}

	@Test
	public void testNullCodeChallengeOrCodeVerifierParameters() throws Exception {
		assertFalse(PkceValidationService.matchWithPattern(null));
	}

	@Test
	public void testValidCodeChallengeParameter() throws Exception {
		assertTrue(PkceValidationService.matchWithPattern(validPlainCodeChallengeOrCodeVerifierParameter1));
	}

	@Test
	public void testInvalidCodeChallengeMethodParameter() throws Exception {
		assertFalse(pkceValidationService.isCodeChallengeMethodSupported(invalidCodeChallengeMethod));
	}

	@Test
	public void testNullCodeChallengeMethodParameter() throws Exception {
		assertFalse(pkceValidationService.isCodeChallengeMethodSupported(null));
	}

	@Test
	public void testNoPkceParametersForEvaluation() throws Exception {
		assertTrue(pkceValidationService.checkAndValidate(authorizeRequestParameters, null));
	}

	@Test(expected = PkceValidationException.class)
	public void testCodeChallengeMissingForEvaluation() throws Exception {
		pkceValidationService.checkAndValidate(authorizeRequestParameters,
				validPlainCodeChallengeOrCodeVerifierParameter1);
	}

	@Test(expected = PkceValidationException.class)
	public void testCodeVerifierMissingForEvaluation() throws Exception {
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
				validPlainCodeChallengeOrCodeVerifierParameter1);
		pkceValidationService.checkAndValidate(authorizeRequestParameters, "");
	}

	@Test(expected = PkceValidationException.class)
	public void testEmptyCodeChallengeMethodForEvaluation() throws Exception {
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
				validPlainCodeChallengeOrCodeVerifierParameter1);
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE_METHOD, "");
		pkceValidationService.checkAndValidate(authorizeRequestParameters,
				validPlainCodeChallengeOrCodeVerifierParameter1);
	}

	@Test
	public void testNoCodeChallengeMethodForEvaluation() throws Exception {
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
				validPlainCodeChallengeOrCodeVerifierParameter1);
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE_METHOD, "plain");
		assertThat(pkceValidationService.checkAndValidate(authorizeRequestParameters,
				validPlainCodeChallengeOrCodeVerifierParameter1), is(true));
	}

	@Test
	public void testNoCodeChallengeMethodForEvaluationWithInvalidPkceParameters() throws Exception {
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
				validPlainCodeChallengeOrCodeVerifierParameter1);
		assertFalse(pkceValidationService.checkAndValidate(authorizeRequestParameters,
				validPlainCodeChallengeOrCodeVerifierParameter2));
	}

	@Test
	public void testPkceValidationServiceConstructorWithCodeChallengeMethodsMap() throws Exception {
		pkceValidationService = new PkceValidationService(createCodeChallengeValidators());
		Set<String> testHashSet = new HashSet<>(Arrays.asList("S256", "plain"));
		assertEquals(testHashSet, pkceValidationService.getSupportedCodeChallengeMethods());
	}
	
	private Map<String,PkceVerifier> createCodeChallengeValidators() {
		S256PkceVerifier s256CodeChallengeMethod = new S256PkceVerifier();
		PlainPkceVerifier plainCodeChallengeValidator = new PlainPkceVerifier();
		Map<String,PkceVerifier> codeChallengeValidators = new HashMap<String, PkceVerifier>();
		codeChallengeValidators.put(plainCodeChallengeValidator.getCodeChallengeMethod(), plainCodeChallengeValidator);
		codeChallengeValidators.put(s256CodeChallengeMethod.getCodeChallengeMethod(), s256CodeChallengeMethod);
		return codeChallengeValidators;
	}
}
