package org.cloudfoundry.identity.uaa.oauth.pkce;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.oauth.pkce.methods.S256CodeChallengeMethod;
import org.junit.Before;
import org.junit.Test;

public class PkceValidationServiceTest {

	private PkceValidationService pkceValidationService;
	private Map<String, String> authorizeRequestParameters;

	private final String longCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cME9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cME9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private final String shortCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c";
	private final String containsForbiddenCharactersCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM%";
	private final String validPlainCodeChallengeOrCodeVerifierParameter1 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private final String validPlainCodeChallengeOrCodeVerifierParameter2 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	private final String invalidCodeChallengeMethodId = "InvalidMethod";
	private final String plainCodeChallengeMethodId = "plain";

	@Before
	public void createPkceValidationService() throws Exception {
		pkceValidationService = new PkceValidationService();
		authorizeRequestParameters = new HashMap<String, String>();
	}

	@Test
	public void testLongCodeChallengeParameter() throws Exception {
		assertFalse(PkceValidationService.isParameterMatchWithPattern(longCodeChallengeOrCodeVerifierParameter));
	}

	@Test
	public void testShortCodeChallengeParameter() throws Exception {
		assertFalse(PkceValidationService.isParameterMatchWithPattern(shortCodeChallengeOrCodeVerifierParameter));
	}

	@Test
	public void testContainsForbiddenCharactersCodeChallengeParameter() throws Exception {
		assertFalse(PkceValidationService
				.isParameterMatchWithPattern(containsForbiddenCharactersCodeChallengeOrCodeVerifierParameter));
	}

	@Test
	public void testNullCodeChallengeParameter() throws Exception {
		assertFalse(PkceValidationService.isParameterMatchWithPattern(null));
	}

	@Test
	public void testEmptyStringCodeChallengeParameter() throws Exception {
		assertFalse(PkceValidationService.isParameterMatchWithPattern(""));
	}

	@Test
	public void testValidCodeChallengeParameter() throws Exception {
		assertTrue(PkceValidationService.isParameterMatchWithPattern(validPlainCodeChallengeOrCodeVerifierParameter1));
	}

	@Test
	public void testInvalidCodeChallengeMethodParameter() throws Exception {
		assertFalse(pkceValidationService.isCodeChallengeMethodSupported(invalidCodeChallengeMethodId));
	}

	@Test
	public void testValidCodeChallengeMethodParameter() throws Exception {
		assertTrue(pkceValidationService.isCodeChallengeMethodSupported(plainCodeChallengeMethodId));
	}

	@Test
	public void testNullCodeChallengeMethodParameter() throws Exception {
		assertFalse(pkceValidationService.isCodeChallengeMethodSupported(null));
	}

	@Test
	public void testEmptyCodeChallengeMethodParameter() throws Exception {
		assertFalse(pkceValidationService.isCodeChallengeMethodSupported(""));
	}
	
	@Test
	public void testPlainCodeChallengeMethodFail() throws Exception {
		PlainCodeChallengeMethod plainCodeChallengeMethod = new PlainCodeChallengeMethod();
		assertFalse(plainCodeChallengeMethod.isCodeVerifierValid("codeVerifier", "codeChallenge"));
	}

	@Test
	public void testPlainCodeChallengeMethodPass() throws Exception {
		PlainCodeChallengeMethod plainCodeChallengeMethod = new PlainCodeChallengeMethod();
		assertTrue(plainCodeChallengeMethod.isCodeVerifierValid("SameString", "SameString"));
	}
	
	@Test
	public void testNoPkceParametersForEvaluation() throws Exception {
		authorizeRequestParameters.put("testParameter1", "testValue1");
		authorizeRequestParameters.put("testParameter2", "testValue2");
		assertTrue(pkceValidationService.evaluateOptionalPkceParameters(authorizeRequestParameters, ""));
	}

	@Test
	public void testCodeChallengeMissingForEvaluation() throws Exception {
		authorizeRequestParameters.put("testParameter1", "testValue1");
		assertFalse(pkceValidationService.evaluateOptionalPkceParameters(authorizeRequestParameters,
				validPlainCodeChallengeOrCodeVerifierParameter1));
	}

	@Test
	public void testCodeVerifierMissingForEvaluation() throws Exception {
		authorizeRequestParameters.put("testParameter1", "testValue1");
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
				validPlainCodeChallengeOrCodeVerifierParameter1);
		assertFalse(pkceValidationService.evaluateOptionalPkceParameters(authorizeRequestParameters, ""));
	}

	@Test
	public void testEmptyCodeChallengeMethodForEvaluation() throws Exception {
		authorizeRequestParameters.put("testParameter1", "testValue1");
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
				validPlainCodeChallengeOrCodeVerifierParameter1);
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE_METHOD, "");
		assertTrue(pkceValidationService.evaluateOptionalPkceParameters(authorizeRequestParameters,
				validPlainCodeChallengeOrCodeVerifierParameter1));
	}

	@Test
	public void testEmptyCodeChallengeMethodForEvaluationWithInvalidPkceParameters() throws Exception {
		authorizeRequestParameters.put("testParameter1", "testValue1");
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
				validPlainCodeChallengeOrCodeVerifierParameter1);
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE_METHOD, "");
		assertFalse(pkceValidationService.evaluateOptionalPkceParameters(authorizeRequestParameters,
				validPlainCodeChallengeOrCodeVerifierParameter2));
	}

	@Test
	public void testNoCodeChallengeMethodForEvaluation() throws Exception {
		authorizeRequestParameters.put("testParameter1", "testValue1");
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
				validPlainCodeChallengeOrCodeVerifierParameter1);
		assertTrue(pkceValidationService.evaluateOptionalPkceParameters(authorizeRequestParameters,
				validPlainCodeChallengeOrCodeVerifierParameter1));
	}

	@Test
	public void testNoCodeChallengeMethodForEvaluationWithInvalidPkceParameters() throws Exception {
		authorizeRequestParameters.put("testParameter1", "testValue1");
		authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
				validPlainCodeChallengeOrCodeVerifierParameter1);
		assertFalse(pkceValidationService.evaluateOptionalPkceParameters(authorizeRequestParameters,
				validPlainCodeChallengeOrCodeVerifierParameter2));
	}

	@Test
	public void testPkceValidationServiceConstructorWithCodeChallengeMethodsMap() throws Exception {
		S256CodeChallengeMethod s256CodeChallengeMethod = new S256CodeChallengeMethod();
		Map<String, CodeChallengeMethod> codeChallengeMethods = new HashMap<String, CodeChallengeMethod>();
		codeChallengeMethods.put(s256CodeChallengeMethod.getCodeChallengeMethodId(), s256CodeChallengeMethod);
		pkceValidationService = new PkceValidationService(codeChallengeMethods);
		Set<String> testHashSet = new HashSet<>(Arrays.asList("S256", "plain"));
		assertEquals(testHashSet, pkceValidationService.getSupportedCodeChallengeMethods());
	}

	@Test
	public void testPkceValidationServiceEmptyConstructor() throws Exception {
		Set<String> testHashSet = new HashSet<>(Arrays.asList("plain"));
		assertEquals(testHashSet, pkceValidationService.getSupportedCodeChallengeMethods());
	}
	
	@Test
	public void testAddCodeChallengeMethod() throws Exception {
		S256CodeChallengeMethod s256CodeChallengeMethod = new S256CodeChallengeMethod();
		pkceValidationService.addcodeChallengeMethod("S256", s256CodeChallengeMethod);
		Set<String> testHashSet = new HashSet<>(Arrays.asList("S256", "plain"));
		assertEquals(testHashSet, pkceValidationService.getSupportedCodeChallengeMethods());
	}

}
