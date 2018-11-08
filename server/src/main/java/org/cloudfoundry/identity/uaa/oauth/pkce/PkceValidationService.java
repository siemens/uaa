package org.cloudfoundry.identity.uaa.oauth.pkce;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PKCE Validation Service.
 *  - Implement and store Plain code challenge method by default.
 *  - Can add further code challenge method implementations.
 *  - Validate code challenge parameter.
 *  - Validate code verifier parameter.
 *  - Validate code challenge method parameter.
 *  - List supported code challenge methods.
 *  - Compare code verifier and code challenge based on code challenge method.
 *
 * @author Zoltan Maradics
 */

public class PkceValidationService {

	/* Regular expression match with any string:
	 *  - Length between 43 and 128 
	 *  - Contains only [A-Z],[a-z],[0-9],_,.,-,~ characters
	 */
	private static final String REGULAR_EXPRESSION_FOR_VALIDATION = "^[\\w\\.\\-\\~]{43,128}$";

	public static final String CODE_CHALLENGE = "code_challenge";
	public static final String CODE_CHALLENGE_METHOD = "code_challenge_method";
	public static final String CODE_VERIFIER = "code_verifier";

	private final Map<String, CodeChallengeMethod> codeChallengeMethods;

	/**
	 * Initialise PCKE Validation service with the list of supported Code Challenge
	 * Methods. Plain code challenge method added by default.
	 * 
	 * @param codeChallengeMethodId
	 *            List of supported code challenge methods
	 */
	public PkceValidationService(Map<String, CodeChallengeMethod> codeChallengeMethods) {
		this.codeChallengeMethods = new HashMap<String, CodeChallengeMethod>(codeChallengeMethods);
		PlainCodeChallengeMethod plainCodeChallengeMethod = new PlainCodeChallengeMethod();
		this.codeChallengeMethods.put(plainCodeChallengeMethod.getCodeChallengeMethodId(), plainCodeChallengeMethod);
	}

	/**
	 * Initialise PCKE Validation service with plain code challenge method by
	 * default.
	 */
	public PkceValidationService() {
		this(Collections.emptyMap());
	}

	/**
	 * Evaluate PKCE parameters from Authorize request and code verifier from Token
	 * request. In case of code challenge method parameter is missing or empty then
	 * the default code challenge method will be used.
	 * 
	 * @param requestParameters
	 *            Stored Authorization request parameters (maybe with
	 *            "code_challenge" and "code_challenge_method").
	 * @param codeVerifier
	 *            Code verifier parameter from token request.
	 * @return true when (1) the requests do not make use of PKCE or when (2) the
	 *         requests make use of PKCE and the parameters have been successfully
	 *         evaluated. false when (1) one of the code_verifier or code_challenge
	 *         are missing or when (2) code_verifier is invalid.
	 */
	public boolean evaluateOptionalPkceParameters(Map<String, String> requestParameters, String codeVerifier) {
		if (!requestParameters.containsKey(CODE_CHALLENGE) && codeVerifier.isEmpty()) {
			// No code challenge and code verifier (Authorization Code Grant without PKCE)
			return true;
		} else if (requestParameters.containsKey(CODE_CHALLENGE) && !codeVerifier.isEmpty()) {
			// There are code challenge and code verifier
			String codeChallenge = requestParameters.get(CODE_CHALLENGE);
			if (requestParameters.containsKey(CODE_CHALLENGE_METHOD)
					&& !requestParameters.get(CODE_CHALLENGE_METHOD).isEmpty()) {
				// Has code challenge method and not empty
				if (isCodeChallengeMethodSupported(requestParameters.get(CODE_CHALLENGE_METHOD))) {
					return codeChallengeMethods.get(requestParameters.get(CODE_CHALLENGE_METHOD))
							.isCodeVerifierValid(codeVerifier, codeChallenge);
				} else {
					// Not supported code challenge method
					return false;
				}
			}
			// No code challenge method or empty => use default: plain
			return codeChallengeMethods.get("plain").isCodeVerifierValid(codeVerifier, codeChallenge);
		}
		return false;
	}

	/**
	 * Possibility to add further supported code challenge method to the existing
	 * supported code challenge methods. Same @id will override the existing one.
	 * 
	 * @param id
	 *            Unique id of code challenge method
	 * @param codeChallengeMethod
	 *            Further supported code challenge method
	 */
	public void addcodeChallengeMethod(String id, CodeChallengeMethod codeChallengeMethod) {
		if (codeChallengeMethod == null) {
			throw new IllegalArgumentException("Code Challenge Method is null");
		}
		this.codeChallengeMethods.put(id, codeChallengeMethod);
	}

	/**
	 * Getter for supported code challenge methods
	 * 
	 * @return Set of supported code challenge methods
	 */
	public Set<String> getSupportedCodeChallengeMethods() {
		return codeChallengeMethods.keySet();
	}

	/**
	 * Compare code challenge method parameter with supported code challenge methods
	 * 
	 * @param codeChallengeMethod
	 *            Code Challenge Method from authorize request
	 * @return true or false based on compare
	 */
	public boolean isCodeChallengeMethodSupported(String codeChallengeMethod) {
		return getSupportedCodeChallengeMethods().contains(codeChallengeMethod);
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

/**
 * Plain code challenge method implementation.
 * 
 * @author Zoltan Maradics
 *
 */
class PlainCodeChallengeMethod implements CodeChallengeMethod {

	private final String codeChallengeMethodId = "plain";

	public PlainCodeChallengeMethod() {
	}

	@Override
	public boolean isCodeVerifierValid(String codeVerifier, String codeChallenge) {
		return codeChallenge.contentEquals(codeVerifier);
	}

	@Override
	public String getCodeChallengeMethodId() {
		return codeChallengeMethodId;
	}

}
