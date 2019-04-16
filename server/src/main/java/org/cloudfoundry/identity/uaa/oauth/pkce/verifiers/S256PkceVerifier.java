package org.cloudfoundry.identity.uaa.oauth.pkce.verifiers;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceVerifier;

/**
 * SHA-256 code challenge method implementation.
 * 
 * @author Zoltan Maradics
 *
 */
public class S256PkceVerifier implements PkceVerifier {

	protected final Log logger = LogFactory.getLog(getClass());
	private final String codeChallengeMethod = "S256";

    public S256PkceVerifier() {
    }

    @Override
    public boolean verify(String codeVerifier, String codeChallenge) {
        if (codeVerifier == null || codeChallenge == null) {
            return false;
        }
        try {
            byte[] bytes = codeVerifier.getBytes("US-ASCII");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes, 0, bytes.length);
            byte[] digest = md.digest();
            return codeChallenge.contentEquals(Base64.encodeBase64URLSafeString(digest));
        } catch (UnsupportedEncodingException e) {
            logger.debug(e.getMessage(),e);
        } catch (NoSuchAlgorithmException e) {
        	logger.debug(e.getMessage(),e);
        }
        return false;
    }

    @Override
    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }
}
