/*
 *******************************************************************
 * Copyright (C) 2018 Siemens AG
 *******************************************************************
 */
package org.cloudfoundry.identity.uaa.oauth.pkce;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PKCE Validation Service.
 *  - Validate Code Verifier parameter.
 *  - Validate Code Challenge parameter.
 *  - Validate Code Challenge Method parameter.
 *  - List supported code challenge methods.
 *  - Compare code verifier and code challenge based on code challenge method.
 *
 * @author Zoltan Maradics
 */

public class PkceValidationService {

	/*
	 * Regular expression match with any string:
	 *  - Length between 43 and 128
	 *  - Contains only [A-Z],[a-z],[0-9],_,.,-,~ characters
	 */
	private static final String REGULAR_EXPRESSION_FOR_VALIDATION = "^[\\w\\.\\-\\~]{43,128}$";

	public static final String CODE_CHALLENGE = "code_challenge";
	public static final String CODE_CHALLENGE_METHOD = "code_challenge_method";
	public static final String CODE_VERIFIER = "code_verifier";

	private Map<String, CodeChallengeValidator> codeChallengeValidators;

	public PkceValidationService(Map<String, CodeChallengeValidator> codeChallengeValidators) {
		if (codeChallengeValidators == null) {
			this.codeChallengeValidators = Collections.emptyMap();
		}
		this.codeChallengeValidators = codeChallengeValidators;
	}

	public PkceValidationService() {
		this(Collections.emptyMap());
	}

	/**
	 * Get all supported code challenge methods.
	 * @return Set of supported code challenge methods.
	 */
	public Set<String> getSupportedCodeChallengeMethods() {
		return this.codeChallengeValidators.keySet();
	}

	/**
	 * Check code challenge method is supported or not.
	 * @param codeChallengeMethod
	 *            Code challenge method parameter.
	 * @return true if Code challenge method in the list of supported code challenge validators.
	 *         false otherwise.
	 */
	public boolean isCodeChallengeMethodSupported(String codeChallengeMethod) {
		if (codeChallengeMethod == null) {
			return false;
		}
		return this.codeChallengeValidators.containsKey(codeChallengeMethod);
	}

	/**
	 * Evaluate PKCE parameters.
	 * 
	 * @param codeChallenge
	 *            Code challenge parameter.
	 * @param codeChallengeMethod
	 *            Code challenge method parameter e.g: "plain", "S256",...
	 * @param codeVerifier
	 *            Code verifier parameter.
	 * @return true when the parameters have been successfully evaluated. 
	 *         false when code_verifier is invalid.
	 * @throws PkceValidationException
	 *         In case of (1) Invalid code challenge parameter.
	 *                    (2) Unsupported code challenge method parameter.
	 *                    (3) Invalid code verifier parameter.
	 */
	public boolean evaluatePkceParameters(String codeChallenge, String codeChallengeMethod, String codeVerifier)
			throws PkceValidationException {
		if (!isCodeChallengeParameterValid(codeChallenge)) {
			throw new PkceValidationException("Invalid code challenge parameter");
		} else if (!isCodeChallengeMethodSupported(codeChallengeMethod)) {
			throw new PkceValidationException("Unsupported code challenge method parameter");
		} else if (!isCodeVerifierParameterValid(codeVerifier)) {
			throw new PkceValidationException("Invalid code verifier parameter");
		}
		return codeChallengeValidators.get(codeChallengeMethod).isCodeVerifierValid(codeVerifier, codeChallenge);
	}
	
	/**
	 * Evaluate PKCE parameters from Authorization request parameters and Code Verifier from Token request.
	 * @param requestParameters
	 *        Authorization request parameters.
	 * @param codeVerifier
	 *        Code verifier from Token request.
	 * @return True: (1) in case of Authorization Code Grand without PKCE
	 *               (2) in case of Authorization Code Grand with PKCE and code verifier
	 *                   matched with code challenge based on code challenge method.
	 *         False: in case of Authorization Code Grand with PKCE and code verifier
	 *                does not match with code challenge based on code challenge method
	 * @throws PkceValidationException
	 *         (1) Missing Code Challenge parameter but has Code Verifier parameter.
	 *         (2) Missing Code Verifier parameter but has Code Challenge parameter.
	 *         (3) Invalid Code Challenge parameter.
	 *         (4) Invalid Code Verifier parameter.
	 *         (5) Unsupported Code Challenge Method.
	 */
	public boolean evaluateOptionalPkceParameters(Map<String, String> requestParameters, String codeVerifier) throws PkceValidationException {
		if (!hasPkceParameters(requestParameters, codeVerifier)) {
			return true;
		}
		String codeChallengeMethod = extractCodeChallengeMethod(requestParameters);
		return evaluatePkceParameters(requestParameters.get(CODE_CHALLENGE), codeChallengeMethod, codeVerifier);
	}
	
	/**
	 * Check Code Challenge and Code Verifier parameters for PKCE 
	 * @param requestParameters
	 *        Authorization request parameters.
	 * @param codeVerifier
	 *        Code Verifier from Token request.
	 * @return True: There are Code Challenge and Code Verifier parameters with not null value.
	 *         False: There is no PKCE parameters.
	 * @throws PkceValidationException
	 *         (1) Missing Code Verifier parameter but has Code Challenge parameter.
	 *         (2) Missing Code Challenge parameter but has Code Verifier parameter.
	 */
	protected static boolean hasPkceParameters(Map<String, String> requestParameters, String codeVerifier) throws PkceValidationException{
		String codeChallenge = requestParameters.get(CODE_CHALLENGE);
		if (codeChallenge != null) {
			if (codeVerifier != null && !codeVerifier.isEmpty()) {
				return true;
			}else {
				throw new PkceValidationException("Missing Code Verifier parameter but has Code Challenge parameter");
			}
		}else if (codeVerifier != null && !codeVerifier.isEmpty()){
			throw new PkceValidationException("Missing Code Challenge parameter but has Code Verifier parameter");
		}
		return false;
	}
	
	/**
	 * Extract code challenge method from request.
	 * @param requestParameters
	 *        Authorization request parameters.
	 * @return
	 * 		  If there is no code challenge method in authorization request then return: "plain"
	 *        Otherwise return the value of code challenge method parameter.
	 */
	protected static String extractCodeChallengeMethod(Map<String, String> requestParameters) {
		String codeChallengeMethod = requestParameters.get(CODE_CHALLENGE_METHOD);
		if (codeChallengeMethod == null) {
			return "plain";
		}else {
			return codeChallengeMethod;
		}
	}
	
	/**
	 * Validate the code verifier parameter based on RFC recommendations.
	 * 
	 * @param codeVerifier
	 *            Code Verifier parameter from token request.
	 * @return true or false based on evaluation.
	 */
	public static boolean isCodeVerifierParameterValid(String codeVerifier) {
		return isParameterMatchWithPattern(codeVerifier);
	}

	/**
	 * Validate the code challenge parameter based on RFC recommendations.
	 * 
	 * @param codeChallenge
	 *            Code Challenge parameter from token request.
	 * @return true or false based on evaluation.
	 */
	public static boolean isCodeChallengeParameterValid(String codeChallenge) {
		return isParameterMatchWithPattern(codeChallenge);
	}

	/**
	 * Validate parameter with predefined regular expression (length and used
	 * character set)
	 * 
	 * @param parameter
	 *            Code Verifier or Code Challenge
	 * @return true or false based on parameter match with regular expression
	 */
	protected static boolean isParameterMatchWithPattern(String parameter) {
		if (parameter == null) {
			return false;
		}
		final Pattern pattern = Pattern.compile(REGULAR_EXPRESSION_FOR_VALIDATION);
		final Matcher matcher = pattern.matcher(parameter);
		return matcher.matches();
	}
}
