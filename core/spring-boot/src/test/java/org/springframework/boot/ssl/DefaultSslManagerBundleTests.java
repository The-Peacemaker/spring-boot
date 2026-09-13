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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.boot.testsupport.system.CapturedOutput;
import org.springframework.boot.testsupport.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link DefaultSslManagerBundle}.
 *
 * @author Phillip Webb
 */
@ExtendWith(OutputCaptureExtension.class)
class DefaultSslManagerBundleTests {

	private static final String CERTIFICATE = """
			-----BEGIN CERTIFICATE-----
			MIIDqzCCApOgAwIBAgIIFMqbpqvipw0wDQYJKoZIhvcNAQELBQAwbDELMAkGA1UE
			BhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVBhbG8gQWx0bzEP
			MA0GA1UEChMGVk13YXJlMQ8wDQYDVQQLEwZTcHJpbmcxEjAQBgNVBAMTCWxvY2Fs
			aG9zdDAgFw0yMzA1MDUxMTI2NThaGA8yMTIzMDQxMTExMjY1OFowbDELMAkGA1UE
			BhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVBhbG8gQWx0bzEP
			MA0GA1UEChMGVk13YXJlMQ8wDQYDVQQLEwZTcHJpbmcxEjAQBgNVBAMTCWxvY2Fs
			aG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPwHWxoE3xjRmNdD
			+m+e/aFlr5wEGQUdWSDD613OB1w7kqO/audEp3c6HxDB3GPcEL0amJwXgY6CQMYu
			sythuZX/EZSc2HdilTBu/5T+mbdWe5JkKThpiA0RYeucQfKuB7zv4ypioa4wiR4D
			nPsZXjg95OF8pCzYEssv8wT49v+M3ohWUgfF0FPlMFCSo0YVTuzB1mhDlWKq/jhQ
			11WpTmk/dQX+l6ts6bYIcJt4uItG+a68a4FutuSjZdTAE0f5SOYRBpGH96mjLwEP
			fW8ZjzvKb9g4R2kiuoPxvCDs1Y/8V2yvKqLyn5Tx9x/DjFmOi0DRK/TgELvNceCb
			UDJmhXMCAwEAAaNPME0wHQYDVR0OBBYEFMBIGU1nwix5RS3O5hGLLoMdR1+NMCwG
			A1UdEQQlMCOCCWxvY2FsaG9zdIcQAAAAAAAAAAAAAAAAAAAAAYcEfwAAATANBgkq
			hkiG9w0BAQsFAAOCAQEAhepfJgTFvqSccsT97XdAZfvB0noQx5NSynRV8NWmeOld
			hHP6Fzj6xCxHSYvlUfmX8fVP9EOAuChgcbbuTIVJBu60rnDT21oOOnp8FvNonCV6
			gJ89sCL7wZ77dw2RKIeUFjXXEV3QJhx2wCOVmLxnJspDoKFIEVjfLyiPXKxqe/6b
			dG8zzWDZ6z+M2JNCtVoOGpljpHqMPCmbDktncv6H3dDTZ83bmLj1nbpOU587gAJ8
			fl1PiUDyPRIl2cnOJd+wCHKsyym/FL7yzk0OSEZ81I92LpGd/0b2Ld3m/bpe+C4Z
			ILzLXTnC6AhrLcDc9QN/EO+BiCL52n7EplNLtSn1LQ==
			-----END CERTIFICATE-----
			""".strip();

	private final KeyManagerFactory keyManagerFactory = mock(KeyManagerFactory.class);

	private final TrustManagerFactory trustManagerFactory = mock(TrustManagerFactory.class);

	@Test
	void getKeyManagerFactoryWhenStoreBundleIsNull() throws Exception {
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(null, SslBundleKey.NONE);
		KeyManagerFactory result = bundle.getKeyManagerFactory();
		assertThat(result).isNotNull();
		then(this.keyManagerFactory).should().init(null, null);
	}

	@Test
	void getKeyManagerFactoryWhenKeyIsNull() throws Exception {
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(SslStoreBundle.NONE, null);
		KeyManagerFactory result = bundle.getKeyManagerFactory();
		assertThat(result).isSameAs(this.keyManagerFactory);
		then(this.keyManagerFactory).should().init(null, null);
	}

	@Test
	void getKeyManagerFactoryWhenHasKeyAliasReturnsWrapped() {
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(null, SslBundleKey.of("secret", "alias"));
		KeyManagerFactory result = bundle.getKeyManagerFactory();
		assertThat(result).isInstanceOf(AliasKeyManagerFactory.class);
	}

	@Test
	void getKeyManagerFactoryWhenHasKeyPassword() throws Exception {
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(null, SslBundleKey.of("secret"));
		KeyManagerFactory result = bundle.getKeyManagerFactory();
		assertThat(result).isSameAs(this.keyManagerFactory);
		then(this.keyManagerFactory).should().init(null, "secret".toCharArray());
	}

	@Test
	void getKeyManagerFactoryWhenHasKeyStorePassword() throws Exception {
		SslStoreBundle storeBundle = SslStoreBundle.of(null, "secret", null);
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(storeBundle, null);
		KeyManagerFactory result = bundle.getKeyManagerFactory();
		assertThat(result).isSameAs(this.keyManagerFactory);
		then(this.keyManagerFactory).should().init(null, "secret".toCharArray());
	}

	@Test
	void getKeyManagerFactoryWhenHasAliasNotInStoreThrowsException() throws Exception {
		KeyStore keyStore = mock(KeyStore.class);
		given(keyStore.containsAlias("alias")).willReturn(false);
		SslStoreBundle storeBundle = SslStoreBundle.of(keyStore, null, null);
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(storeBundle,
				SslBundleKey.of("secret", "alias"));
		assertThatIllegalStateException().isThrownBy(bundle::getKeyManagerFactory)
			.withMessage("Keystore does not contain alias 'alias'");
	}

	@Test
	void getKeyManagerFactoryWhenHasAliasNotDeterminedInStoreThrowsException() throws Exception {
		KeyStore keyStore = mock(KeyStore.class);
		given(keyStore.containsAlias("alias")).willThrow(KeyStoreException.class);
		SslStoreBundle storeBundle = SslStoreBundle.of(keyStore, null, null);
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(storeBundle,
				SslBundleKey.of("secret", "alias"));
		assertThatIllegalStateException().isThrownBy(bundle::getKeyManagerFactory)
			.withMessage("Could not determine if keystore contains alias 'alias'");
	}

	@Test
	void getKeyManagerFactoryWhenAliasIsNotKeyEntryLogsWarning(CapturedOutput output) throws Exception {
		KeyStore keyStore = mock(KeyStore.class);
		given(keyStore.containsAlias("alias")).willReturn(true);
		given(keyStore.getProvider()).willReturn(Security.getProvider("SUN"));
		given(keyStore.isKeyEntry("alias")).willReturn(false);
		SslStoreBundle storeBundle = SslStoreBundle.of(keyStore, null, null);
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(storeBundle,
				SslBundleKey.of("secret", "alias"));
		assertThat(bundle.getKeyManagerFactory()).isSameAs(this.keyManagerFactory);
		then(this.keyManagerFactory).should().init(keyStore, "secret".toCharArray());
		assertThat(output).contains("Keystore alias 'alias' is not a key entry");
	}

	@Test
	void getKeyManagerFactoryWhenAliasHasNoCertificateChainLogsWarning(CapturedOutput output) throws Exception {
		KeyStore keyStore = mock(KeyStore.class);
		given(keyStore.containsAlias("alias")).willReturn(true);
		given(keyStore.getProvider()).willReturn(Security.getProvider("SUN"));
		given(keyStore.isKeyEntry("alias")).willReturn(true);
		given(keyStore.getCertificateChain("alias")).willReturn(null);
		SslStoreBundle storeBundle = SslStoreBundle.of(keyStore, null, null);
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(storeBundle,
				SslBundleKey.of("secret", "alias"));
		assertThat(bundle.getKeyManagerFactory()).isSameAs(this.keyManagerFactory);
		then(this.keyManagerFactory).should().init(keyStore, "secret".toCharArray());
		assertThat(output).contains("Keystore alias 'alias' does not have an associated certificate chain");
	}

	@Test
	void getKeyManagerFactoryWhenAliasIsTrustedCertificateEntryLogsWarning(CapturedOutput output) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);
		keyStore.setCertificateEntry("alias", parseCertificate(CERTIFICATE));
		SslStoreBundle storeBundle = SslStoreBundle.of(keyStore, null, null);
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(storeBundle,
				SslBundleKey.of("secret", "alias"));
		assertThat(bundle.getKeyManagerFactory()).isSameAs(this.keyManagerFactory);
		then(this.keyManagerFactory).should().init(keyStore, "secret".toCharArray());
		assertThat(output).contains("Keystore alias 'alias' is not a key entry");
	}

	@Test
	void getKeyManagerFactoryWhenKeyStoreProviderIsNotSunLogsNoWarning(CapturedOutput output) throws Exception {
		KeyStore keyStore = mock(KeyStore.class);
		given(keyStore.containsAlias("alias")).willReturn(true);
		given(keyStore.getProvider()).willReturn(new Provider("Test", "1.0", "Test provider") {
		});
		SslStoreBundle storeBundle = SslStoreBundle.of(keyStore, null, null);
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(storeBundle,
				SslBundleKey.of("secret", "alias"));
		assertThat(bundle.getKeyManagerFactory()).isSameAs(this.keyManagerFactory);
		then(this.keyManagerFactory).should().init(keyStore, "secret".toCharArray());
		assertThat(output).doesNotContain("is not a key entry");
		assertThat(output).doesNotContain("certificate chain");
	}

	@Test
	void getKeyManagerFactoryWhenAliasIsValidKeyEntryLogsNoWarning(CapturedOutput output) throws Exception {
		KeyStore keyStore = mock(KeyStore.class);
		given(keyStore.containsAlias("alias")).willReturn(true);
		given(keyStore.getProvider()).willReturn(Security.getProvider("SUN"));
		given(keyStore.isKeyEntry("alias")).willReturn(true);
		given(keyStore.getCertificateChain("alias")).willReturn(new Certificate[] { mock(Certificate.class) });
		SslStoreBundle storeBundle = SslStoreBundle.of(keyStore, null, null);
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(storeBundle,
				SslBundleKey.of("secret", "alias"));
		assertThat(bundle.getKeyManagerFactory()).isSameAs(this.keyManagerFactory);
		then(this.keyManagerFactory).should().init(keyStore, "secret".toCharArray());
		assertThat(output).doesNotContain("is not a key entry");
		assertThat(output).doesNotContain("certificate chain");
	}

	@Test
	void getKeyManagerFactoryWhenKeyEntryValidationFailsLogsNoWarning(CapturedOutput output) throws Exception {
		KeyStore keyStore = mock(KeyStore.class);
		given(keyStore.containsAlias("alias")).willReturn(true);
		given(keyStore.getProvider()).willReturn(Security.getProvider("SUN"));
		given(keyStore.isKeyEntry("alias")).willThrow(KeyStoreException.class);
		SslStoreBundle storeBundle = SslStoreBundle.of(keyStore, null, null);
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(storeBundle,
				SslBundleKey.of("secret", "alias"));
		assertThat(bundle.getKeyManagerFactory()).isSameAs(this.keyManagerFactory);
		then(this.keyManagerFactory).should().init(keyStore, "secret".toCharArray());
		assertThat(output).doesNotContain("is not a key entry");
		assertThat(output).doesNotContain("certificate chain");
	}

	@Test
	void getKeyManagerFactoryWhenHasStore() throws Exception {
		KeyStore keyStore = mock(KeyStore.class);
		SslStoreBundle storeBundle = SslStoreBundle.of(keyStore, null, null);
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(storeBundle, null);
		KeyManagerFactory result = bundle.getKeyManagerFactory();
		assertThat(result).isSameAs(this.keyManagerFactory);
		then(this.keyManagerFactory).should().init(keyStore, null);
	}

	@Test
	void getTrustManagerFactoryWhenStoreBundleIsNull() throws Exception {
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(null, null);
		TrustManagerFactory result = bundle.getTrustManagerFactory();
		assertThat(result).isSameAs(this.trustManagerFactory);
		then(this.trustManagerFactory).should().init((KeyStore) null);
	}

	@Test
	void getTrustManagerFactoryWhenHasStore() throws Exception {
		KeyStore trustStore = mock(KeyStore.class);
		SslStoreBundle storeBundle = SslStoreBundle.of(null, null, trustStore);
		DefaultSslManagerBundle bundle = new TestDefaultSslManagerBundle(storeBundle, null);
		TrustManagerFactory result = bundle.getTrustManagerFactory();
		assertThat(result).isSameAs(this.trustManagerFactory);
		then(this.trustManagerFactory).should().init(trustStore);
	}

	private static Certificate parseCertificate(String content) throws Exception {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		try (ByteArrayInputStream input = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8))) {
			return factory.generateCertificate(input);
		}
	}

	/**
	 * Test version of {@link DefaultSslManagerBundle}.
	 */
	class TestDefaultSslManagerBundle extends DefaultSslManagerBundle {

		TestDefaultSslManagerBundle(@Nullable SslStoreBundle storeBundle, @Nullable SslBundleKey key) {
			super(storeBundle, key);
		}

		@Override
		protected KeyManagerFactory getKeyManagerFactoryInstance(String algorithm) throws NoSuchAlgorithmException {
			return DefaultSslManagerBundleTests.this.keyManagerFactory;
		}

		@Override
		protected TrustManagerFactory getTrustManagerFactoryInstance(String algorithm) throws NoSuchAlgorithmException {
			return DefaultSslManagerBundleTests.this.trustManagerFactory;
		}

	}

}
