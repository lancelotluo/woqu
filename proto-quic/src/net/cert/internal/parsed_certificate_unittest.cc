// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/parsed_certificate.h"

#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/parse_certificate.h"
#include "net/cert/internal/test_helpers.h"
#include "net/der/input.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/pool.h"

namespace net {

namespace {

std::string GetFilePath(const std::string& file_name) {
  return std::string("net/data/parse_certificate_unittest/") + file_name;
}

// Reads and parses a certificate from the PEM file |file_name|.
//
// Returns nullptr if the certificate parsing failed, and verifies that any
// errors match the ERRORS block in the .pem file.
scoped_refptr<ParsedCertificate> ParseCertificateFromFile(
    const std::string& file_name,
    const ParseCertificateOptions& options) {
  std::string data;
  std::string expected_errors;

  // Read the certificate data and error expectations from a single PEM file.
  const PemBlockMapping mappings[] = {
      {"CERTIFICATE", &data}, {"ERRORS", &expected_errors, true /*optional*/},
  };
  std::string test_file_path = GetFilePath(file_name);
  EXPECT_TRUE(ReadTestDataFromPemFile(test_file_path, mappings));

  CertErrors errors;
  scoped_refptr<ParsedCertificate> cert = ParsedCertificate::Create(
      bssl::UniquePtr<CRYPTO_BUFFER>(CRYPTO_BUFFER_new(
          reinterpret_cast<const uint8_t*>(data.data()), data.size(), nullptr)),
      options, &errors);

  EXPECT_EQ(expected_errors, errors.ToDebugString()) << "Test file: "
                                                     << test_file_path;

  // TODO(crbug.com/634443): Every parse failure being tested should emit error
  // information.
  // if (!cert)
  //   EXPECT_FALSE(errors.empty());

  return cert;
}

der::Input DavidBenOid() {
  // This OID corresponds with
  // 1.2.840.113554.4.1.72585.0 (https://davidben.net/oid)
  static const uint8_t kOid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12,
                                 0x04, 0x01, 0x84, 0xb7, 0x09, 0x00};
  return der::Input(kOid);
}

// Parses an Extension whose critical field is true (255).
TEST(ParsedCertificateTest, ExtensionCritical) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("extension_critical.pem", {});
  ASSERT_TRUE(cert);

  const uint8_t kExpectedValue[] = {0x30, 0x00};

  ParsedExtension extension;
  ASSERT_TRUE(cert->GetExtension(DavidBenOid(), &extension));

  EXPECT_TRUE(extension.critical);
  EXPECT_EQ(DavidBenOid(), extension.oid);
  EXPECT_EQ(der::Input(kExpectedValue), extension.value);
}

// Parses an Extension whose critical field is false (omitted).
TEST(ParsedCertificateTest, ExtensionNotCritical) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("extension_not_critical.pem", {});
  ASSERT_TRUE(cert);

  const uint8_t kExpectedValue[] = {0x30, 0x00};

  ParsedExtension extension;
  ASSERT_TRUE(cert->GetExtension(DavidBenOid(), &extension));

  EXPECT_FALSE(extension.critical);
  EXPECT_EQ(DavidBenOid(), extension.oid);
  EXPECT_EQ(der::Input(kExpectedValue), extension.value);
}

// Parses an Extension whose critical field is 0. This is in one sense FALSE,
// however because critical has DEFAULT of false this is in fact invalid
// DER-encoding.
TEST(ParsedCertificateTest, ExtensionCritical0) {
  ASSERT_FALSE(ParseCertificateFromFile("extension_critical_0.pem", {}));
}

// Parses an Extension whose critical field is 3. Under DER-encoding BOOLEAN
// values must an octet of either all zero bits, or all 1 bits, so this is not
// valid.
TEST(ParsedCertificateTest, ExtensionCritical3) {
  ASSERT_FALSE(ParseCertificateFromFile("extension_critical_3.pem", {}));
}

// Parses an Extensions that is an empty sequence.
TEST(ParsedCertificateTest, ExtensionsEmptySequence) {
  ASSERT_FALSE(ParseCertificateFromFile("extensions_empty_sequence.pem", {}));
}

// Parses an Extensions that is not a sequence.
TEST(ParsedCertificateTest, ExtensionsNotSequence) {
  ASSERT_FALSE(ParseCertificateFromFile("extensions_not_sequence.pem", {}));
}

// Parses an Extensions that has data after the sequence.
TEST(ParsedCertificateTest, ExtensionsDataAfterSequence) {
  ASSERT_FALSE(
      ParseCertificateFromFile("extensions_data_after_sequence.pem", {}));
}

// Parses an Extensions that contains duplicated key usages.
TEST(ParsedCertificateTest, ExtensionsDuplicateKeyUsage) {
  ASSERT_FALSE(
      ParseCertificateFromFile("extensions_duplicate_key_usage.pem", {}));
}

// Parses an Extensions that contains an extended key usages.
TEST(ParsedCertificateTest, ExtendedKeyUsage) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("extended_key_usage.pem", {});
  ASSERT_TRUE(cert);

  ASSERT_EQ(4u, cert->extensions().size());

  ParsedExtension extension;
  ASSERT_TRUE(cert->GetExtension(ExtKeyUsageOid(), &extension));

  EXPECT_FALSE(extension.critical);
  EXPECT_EQ(45u, extension.value.Length());

  EXPECT_TRUE(cert->has_extended_key_usage());
  EXPECT_EQ(4u, cert->extended_key_usage().size());
}

// Parses an Extensions that contains a key usage.
TEST(ParsedCertificateTest, KeyUsage) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("key_usage.pem", {});
  ASSERT_TRUE(cert);

  ASSERT_TRUE(cert->has_key_usage());

  EXPECT_EQ(5u, cert->key_usage().unused_bits());
  const uint8_t kExpectedBytes[] = {0xA0};
  EXPECT_EQ(der::Input(kExpectedBytes), cert->key_usage().bytes());

  EXPECT_TRUE(cert->key_usage().AssertsBit(0));
  EXPECT_FALSE(cert->key_usage().AssertsBit(1));
  EXPECT_TRUE(cert->key_usage().AssertsBit(2));
}

// Parses an Extensions that contains a policies extension.
TEST(ParsedCertificateTest, Policies) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("policies.pem", {});
  ASSERT_TRUE(cert);

  ASSERT_EQ(4u, cert->extensions().size());

  ParsedExtension extension;
  ASSERT_TRUE(cert->GetExtension(CertificatePoliciesOid(), &extension));

  EXPECT_FALSE(extension.critical);
  EXPECT_EQ(95u, extension.value.Length());

  EXPECT_TRUE(cert->has_policy_oids());
  EXPECT_EQ(2u, cert->policy_oids().size());
}

// Parses an Extensions that contains a subjectaltname extension.
TEST(ParsedCertificateTest, SubjectAltName) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("subject_alt_name.pem", {});
  ASSERT_TRUE(cert);

  ASSERT_TRUE(cert->has_subject_alt_names());
}

// Parses an Extensions that contains multiple extensions, sourced from a
// real-world certificate.
TEST(ParsedCertificateTest, ExtensionsReal) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("extensions_real.pem", {});
  ASSERT_TRUE(cert);

  ASSERT_EQ(7u, cert->extensions().size());

  EXPECT_TRUE(cert->has_key_usage());
  EXPECT_TRUE(cert->has_basic_constraints());
  EXPECT_TRUE(cert->has_policy_oids());

  ParsedExtension extension;
  ASSERT_TRUE(cert->GetExtension(CertificatePoliciesOid(), &extension));

  EXPECT_FALSE(extension.critical);
  EXPECT_EQ(16u, extension.value.Length());

  // TODO(eroman): Verify the other 4 extensions' values.
}

// Parses a BasicConstraints with no CA or pathlen.
TEST(ParsedCertificateTest, BasicConstraintsNotCa) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("basic_constraints_not_ca.pem", {});
  ASSERT_TRUE(cert);

  EXPECT_TRUE(cert->has_basic_constraints());
  EXPECT_FALSE(cert->basic_constraints().is_ca);
  EXPECT_FALSE(cert->basic_constraints().has_path_len);
}

// Parses a BasicConstraints with CA but no pathlen.
TEST(ParsedCertificateTest, BasicConstraintsCaNoPath) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("basic_constraints_ca_no_path.pem", {});
  ASSERT_TRUE(cert);

  EXPECT_TRUE(cert->has_basic_constraints());
  EXPECT_TRUE(cert->basic_constraints().is_ca);
  EXPECT_FALSE(cert->basic_constraints().has_path_len);
}

// Parses a BasicConstraints with CA and pathlen of 9.
TEST(ParsedCertificateTest, BasicConstraintsCaPath9) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("basic_constraints_ca_path_9.pem", {});
  ASSERT_TRUE(cert);

  EXPECT_TRUE(cert->has_basic_constraints());
  EXPECT_TRUE(cert->basic_constraints().is_ca);
  EXPECT_TRUE(cert->basic_constraints().has_path_len);
  EXPECT_EQ(9u, cert->basic_constraints().path_len);
}

// Parses a BasicConstraints with CA and pathlen of 255 (largest allowed size).
TEST(ParsedCertificateTest, BasicConstraintsPathlen255) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("basic_constraints_pathlen_255.pem", {});
  ASSERT_TRUE(cert);

  EXPECT_TRUE(cert->has_basic_constraints());
  EXPECT_TRUE(cert->basic_constraints().is_ca);
  EXPECT_TRUE(cert->basic_constraints().has_path_len);
  EXPECT_EQ(255, cert->basic_constraints().path_len);
}

// Parses a BasicConstraints with CA and pathlen of 256 (too large).
TEST(ParsedCertificateTest, BasicConstraintsPathlen256) {
  ASSERT_FALSE(
      ParseCertificateFromFile("basic_constraints_pathlen_256.pem", {}));
}

// Parses a BasicConstraints with CA and a negative pathlen.
TEST(ParsedCertificateTest, BasicConstraintsNegativePath) {
  ASSERT_FALSE(
      ParseCertificateFromFile("basic_constraints_negative_path.pem", {}));
}

// Parses a BasicConstraints with CA and pathlen that is very large (and
// couldn't fit in a 64-bit integer).
TEST(ParsedCertificateTest, BasicConstraintsPathTooLarge) {
  ASSERT_FALSE(
      ParseCertificateFromFile("basic_constraints_path_too_large.pem", {}));
}

// Parses a BasicConstraints with CA explicitly set to false. This violates
// DER-encoding rules, however is commonly used, so it is accepted.
TEST(ParsedCertificateTest, BasicConstraintsCaFalse) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("basic_constraints_ca_false.pem", {});
  ASSERT_TRUE(cert);

  EXPECT_TRUE(cert->has_basic_constraints());
  EXPECT_FALSE(cert->basic_constraints().is_ca);
  EXPECT_FALSE(cert->basic_constraints().has_path_len);
}

// Parses a BasicConstraints with CA set to true and an unexpected NULL at
// the end.
TEST(ParsedCertificateTest, BasicConstraintsUnconsumedData) {
  ASSERT_FALSE(
      ParseCertificateFromFile("basic_constraints_unconsumed_data.pem", {}));
}

// Parses a BasicConstraints with CA omitted (false), but with a pathlen of 1.
// This is valid DER for the ASN.1, however is not valid when interpreting the
// BasicConstraints at a higher level.
TEST(ParsedCertificateTest, BasicConstraintsPathLenButNotCa) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("basic_constraints_pathlen_not_ca.pem", {});
  ASSERT_TRUE(cert);

  EXPECT_TRUE(cert->has_basic_constraints());
  EXPECT_FALSE(cert->basic_constraints().is_ca);
  EXPECT_TRUE(cert->basic_constraints().has_path_len);
  EXPECT_EQ(1u, cert->basic_constraints().path_len);
}

// Tests parsing a certificate that contains a policyConstraints
// extension having requireExplicitPolicy:3.
TEST(ParsedCertificateTest, PolicyConstraintsRequire) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("policy_constraints_require.pem", {});
  ASSERT_TRUE(cert);

  EXPECT_TRUE(cert->has_policy_constraints());
  EXPECT_TRUE(cert->policy_constraints().has_require_explicit_policy);
  EXPECT_EQ(3, cert->policy_constraints().require_explicit_policy);
  EXPECT_FALSE(cert->policy_constraints().has_inhibit_policy_mapping);
  EXPECT_EQ(0, cert->policy_constraints().inhibit_policy_mapping);
}

// Tests parsing a certificate that contains a policyConstraints
// extension having inhibitPolicyMapping:1.
TEST(ParsedCertificateTest, PolicyConstraintsInhibit) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("policy_constraints_inhibit.pem", {});
  ASSERT_TRUE(cert);

  EXPECT_TRUE(cert->has_policy_constraints());
  EXPECT_FALSE(cert->policy_constraints().has_require_explicit_policy);
  EXPECT_EQ(0, cert->policy_constraints().require_explicit_policy);
  EXPECT_TRUE(cert->policy_constraints().has_inhibit_policy_mapping);
  EXPECT_EQ(1, cert->policy_constraints().inhibit_policy_mapping);
}

// Tests parsing a certificate that contains a policyConstraints
// extension having requireExplicitPolicy:5,inhibitPolicyMapping:2.
TEST(ParsedCertificateTest, PolicyConstraintsInhibitRequire) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("policy_constraints_inhibit_require.pem", {});
  ASSERT_TRUE(cert);

  EXPECT_TRUE(cert->has_policy_constraints());
  EXPECT_TRUE(cert->policy_constraints().has_require_explicit_policy);
  EXPECT_EQ(5, cert->policy_constraints().require_explicit_policy);
  EXPECT_TRUE(cert->policy_constraints().has_inhibit_policy_mapping);
  EXPECT_EQ(2, cert->policy_constraints().inhibit_policy_mapping);
}

// Tests parsing a certificate that has a policyConstraints
// extension with an empty sequence.
TEST(ParsedCertificateTest, PolicyConstraintsEmpty) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("policy_constraints_empty.pem", {});
  ASSERT_FALSE(cert);
}

// Tests a certificate with a serial number with a leading 0 padding byte in
// the encoding since it is not negative.
TEST(ParsedCertificateTest, SerialNumberZeroPadded) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("serial_zero_padded.pem", {});
  ASSERT_TRUE(cert);

  static const uint8_t expected_serial[3] = {0x00, 0x80, 0x01};
  EXPECT_EQ(der::Input(expected_serial), cert->tbs().serial_number);
}

// Tests a serial number where the MSB is >= 0x80, causing the encoded
// length to be 21 bytes long. This is an error, as RFC 5280 specifies a
// maximum of 20 bytes.
TEST(ParsedCertificateTest, SerialNumberZeroPadded21BytesLong) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("serial_zero_padded_21_bytes.pem", {});
  ASSERT_FALSE(cert);

  // Try again with allow_invalid_serial_numbers=true. Parsing should succeed.
  ParseCertificateOptions options;
  options.allow_invalid_serial_numbers = true;
  cert = ParseCertificateFromFile("serial_zero_padded_21_bytes.pem", options);
  ASSERT_TRUE(cert);

  static const uint8_t expected_serial[21] = {
      0x00, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
      0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13};
  EXPECT_EQ(der::Input(expected_serial), cert->tbs().serial_number);
}

// Tests a serial number which is negative.  CAs are not supposed to include
// negative serial numbers, however RFC 5280 expects consumers to deal with it
// anyway.
TEST(ParsedCertificateTest, SerialNumberNegative) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("serial_negative.pem", {});
  ASSERT_TRUE(cert);

  static const uint8_t expected_serial[2] = {0x80, 0x01};
  EXPECT_EQ(der::Input(expected_serial), cert->tbs().serial_number);
}

// Tests a serial number which is very long. RFC 5280 specifies a maximum of 20
// bytes.
TEST(ParsedCertificateTest, SerialNumber37BytesLong) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("serial_37_bytes.pem", {});
  ASSERT_FALSE(cert);

  // Try again with allow_invalid_serial_numbers=true. Parsing should succeed.
  ParseCertificateOptions options;
  options.allow_invalid_serial_numbers = true;
  cert = ParseCertificateFromFile("serial_37_bytes.pem", options);
  ASSERT_TRUE(cert);

  static const uint8_t expected_serial[37] = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
      0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
      0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25};
  EXPECT_EQ(der::Input(expected_serial), cert->tbs().serial_number);
}

// Tests parsing a certificate that has an inhibitAnyPolicy extension.
TEST(ParsedCertificateTest, InhibitAnyPolicy) {
  scoped_refptr<ParsedCertificate> cert =
      ParseCertificateFromFile("inhibit_any_policy.pem", {});
  ASSERT_TRUE(cert);

  ParsedExtension extension;
  ASSERT_TRUE(cert->GetExtension(InhibitAnyPolicyOid(), &extension));

  uint8_t skip_count;
  ASSERT_TRUE(ParseInhibitAnyPolicy(extension.value, &skip_count));
  EXPECT_EQ(3, skip_count);
}

}  // namespace

}  // namespace net
