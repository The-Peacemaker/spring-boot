/*
 * Copyright 2012-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.ssl;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.core.log.LogMessage;
import org.springframework.util.StringUtils;

/**
 * Default implementation of {@link SslManagerBundle}.
 *
 * @author Scott Frederick
 * @see SslManagerBundle#from(SslStoreBundle, SslBundleKey)
 */
class DefaultSslManagerBundle implements SslManagerBundle {

	private static final Log logger = LogFactory.getLog(DefaultSslManagerBundle.class);

	private final SslStoreBundle storeBundle;

	private final SslBundleKey key;

	DefaultSslManagerBundle(@Nullable SslStoreBundle storeBundle, @Nullable SslBundleKey key) {
		this.storeBundle = (storeBundle != null) ? storeBundle : SslStoreBundle.NONE;
		this.key = (key != null) ? key : SslBundleKey.NONE;
	}

	@Override
	public KeyManagerFactory getKeyManagerFactory() {
		try {
			KeyStore store = this.storeBundle.getKeyStore();
			this.key.assertContainsAlias(store);
			logWarningIfKeyEntryIsSuspicious(store);
			String alias = this.key.getAlias();
			String algorithm = KeyManagerFactory.getDefaultAlgorithm();
			KeyManagerFactory factory = getKeyManagerFactoryInstance(algorithm);
			factory = (alias != null) ? new AliasKeyManagerFactory(factory, alias, algorithm) : factory;
			String password = this.key.getPassword();
			password = (password != null) ? password : this.storeBundle.getKeyStorePassword();
			factory.init(store, (password != null) ? password.toCharArray() : null);
			return factory;
		}
		catch (RuntimeException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new IllegalStateException("Could not load key manager factory: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Log a warning if the configured key alias does not resolve to a usable key
	 * entry with a certificate chain. This check is best-effort only and never
	 * throws: a validation failure must never break startup. It exists so that a
	 * broken entry fails loudly in the logs rather than cryptically during the TLS
	 * handshake. Only keystores backed by the SUN provider are checked since it is
	 * the only provider known to silently drop certificates when loading a
	 * passwordless PKCS12 store. Other providers are never checked so that no
	 * false-positive warning can be logged for them.
	 * @param store the keystore to check
	 */
	private void logWarningIfKeyEntryIsSuspicious(@Nullable KeyStore store) {
		String alias = this.key.getAlias();
		if (!StringUtils.hasLength(alias) || store == null || !isSunProvider(store)) {
			return;
		}
		try {
			if (!store.isKeyEntry(alias)) {
				logger.warn(LogMessage.format(
						"Keystore alias '%s' is not a key entry. TLS handshakes using this bundle may fail with errors such as 'SSL_ERROR_NO_CYPHER_OVERLAP'. If you are using a passwordless PKCS12 keystore, the JDK may have silently dropped the certificate entries when loading the store.",
						alias));
			}
			else {
				Certificate[] chain = store.getCertificateChain(alias);
				if (chain == null || chain.length == 0) {
					logger.warn(LogMessage.format(
							"Keystore alias '%s' does not have an associated certificate chain. TLS handshakes using this bundle may fail with errors such as 'SSL_ERROR_NO_CYPHER_OVERLAP'. If you are using a passwordless PKCS12 keystore, the JDK may have silently dropped the certificates when loading the store.",
							alias));
				}
			}
		}
		catch (Exception ex) {
			logger.debug(LogMessage.format("Could not validate keystore alias '%s'", alias), ex);
		}
	}

	/**
	 * Whether the given keystore is backed by the SUN provider.
	 * @param store the keystore to check
	 * @return {@code true} if the SUN provider backs the keystore
	 */
	private static boolean isSunProvider(KeyStore store) {
		return "SUN".equals(store.getProvider().getName());
	}

	@Override
	public TrustManagerFactory getTrustManagerFactory() {
		try {
			KeyStore store = this.storeBundle.getTrustStore();
			String algorithm = TrustManagerFactory.getDefaultAlgorithm();
			TrustManagerFactory factory = getTrustManagerFactoryInstance(algorithm);
			factory.init(store);
			return factory;
		}
		catch (Exception ex) {
			throw new IllegalStateException("Could not load trust manager factory: " + ex.getMessage(), ex);
		}
	}

	protected KeyManagerFactory getKeyManagerFactoryInstance(String algorithm) throws NoSuchAlgorithmException {
		return KeyManagerFactory.getInstance(algorithm);
	}

	protected TrustManagerFactory getTrustManagerFactoryInstance(String algorithm) throws NoSuchAlgorithmException {
		return TrustManagerFactory.getInstance(algorithm);
	}

}
