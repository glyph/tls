from __future__ import absolute_import, division, print_function

from tls.hello_message import ClientHello, ProtocolVersion, ServerHello

from tls.message import (
    Certificate, CertificateRequest, ClientCertificateType, Handshake,
    HandshakeType, HashAlgorithm, HelloRequest, PreMasterSecret,
    ServerHelloDone, SignatureAlgorithm, parse_certificate,
    parse_certificate_request, parse_handshake_struct, parse_pre_master_secret,
    parse_server_dh_params
)


class TestCertificateRequestParsing(object):
    """
    Tests for parsing of CertificateRequest messages.
    """

    def test_parse_certificate_request(self):
        packet = (
            b'\x01'  # certificate_types length
            b'\x01'  # certificate_types
            b'\x00\x02'  # supported_signature_algorithms length
            b'\x01'  # supported_signature_algorithms.hash
            b'\x01'  # supported_signature_algorithms.signature
            b'\x00\x00'  # certificate_authorities length
            b''  # certificate_authorities
        )
        record = parse_certificate_request(packet)
        assert record.certificate_types == [ClientCertificateType.RSA_SIGN]
        assert len(record.supported_signature_algorithms) == 1
        assert record.supported_signature_algorithms[0].hash == \
            HashAlgorithm.MD5
        assert record.supported_signature_algorithms[0].signature == \
            SignatureAlgorithm.RSA
        assert record.certificate_authorities == b''

    def test_parse_certificate_request_with_authorities(self):
        packet = (
            b'\x01'  # certificate_types length
            b'\x01'  # certificate_types
            b'\x00\x02'  # supported_signature_algorithms length
            b'\x01'  # supported_signature_algorithms.hash
            b'\x01'  # supported_signature_algorithms.signature
            b'\x00\x02'  # certificate_authorities length
            b'03'  # certificate_authorities
        )
        record = parse_certificate_request(packet)
        assert record.certificate_authorities == b'03'


class TestServerDHParamsparsing(object):
    """
    Tests for parsing of ServerDHParams struct.
    """

    def test_parse_struct(self):
        packet = (
            b'\x00\x03'
            b'123'
            b'\x00\x04'
            b'5678'
            b'\x00\x02'
            b'78'
        )
        record = parse_server_dh_params(packet)
        assert record.dh_p == b'123'
        assert record.dh_g == b'5678'
        assert record.dh_Ys == b'78'


class TestPreMasterSecretParsing(object):
    """
    Tests for parsing of PreMasterSecret struct.
    """

    def test_parse_pre_master_secret(self):
        import os
        r = os.urandom(46)
        packet = (
            b'\x03\x00'  # ClientHello.client_version
            + r
        )
        record = parse_pre_master_secret(packet)
        assert isinstance(record, PreMasterSecret)
        assert isinstance(record.client_version, ProtocolVersion)
        assert record.client_version.major == 3
        assert record.client_version.minor == 0
        assert record.random == r


class TestCertificateParsing(object):
    """
    Tests for parsing of Certificate messages.
    """

    def test_parse_certificate(self):
        packet = (
            b'\x00\x00\x00\x07'  # certificate_length
            b'\x00\x00\x00\x03'  # certificate_list.asn1_cert length
            b'ABC'  # certificate_list.asn1_cert
        )
        record = parse_certificate(packet)
        assert isinstance(record, Certificate)
        assert record.certificate_list == [b'ABC']


class TestHandshakeStructParsing(object):
    """
    Tests for parsing of Handshake structs.
    """

    def test_parse_client_hello_in_handshake(self):
        client_hello_packet = (
            b'\x03\x00'  # client_version
            b'\x01\x02\x03\x04'  # random.gmt_unix_time
            b'0123456789012345678901234567'  # random.random_bytes
            b'\x00'  # session_id.length
            b''  # session_id.session_id
            b'\x00\x02'  # cipher_suites length
            b'\x00\x6B'  # cipher_suites
            b'\x01'  # compression_methods length
            b'\x00'  # compression_methods
            b'\x00\x08'  # extensions length
            b'\x00\x0D'  # extensions.extensions.extension_type
            b'\x00\x04'  # extensions.extensions.extensions_data length
            b'abcd'  # extensions.extensions.extension_data
        )

        handshake_packet = (
            b'\x01'  # msg_type
            b'\x00\x00\x003'  # body length
        ) + client_hello_packet

        record = parse_handshake_struct(handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.CLIENT_HELLO
        assert record.length == 51
        assert isinstance(record.body, ClientHello)

    def test_parse_server_hello_in_handshake(self):
        server_hello_packet = (
            b'\x03\x00'  # server_version
            b'\x01\x02\x03\x04'  # random.gmt_unix_time
            b'0123456789012345678901234567'  # random.random_bytes
            b'\x20'  # session_id.length
            b'01234567890123456789012345678901'  # session_id
            b'\x00\x6B'  # cipher_suite
            b'\x00'  # compression_method
            b'\x00\x08'  # extensions.length
            b'\x00\x0D'  # extensions.extensions.extension_type
            b'\x00\x04'  # extensions.extensions.extensions_data length
            b'abcd'  # extensions.extensions.extension_data
        )

        handshake_packet = (
            b'\x02'  # msg_type
            b'\x00\x00\x00P'  # body length
        ) + server_hello_packet

        record = parse_handshake_struct(handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.SERVER_HELLO
        assert record.length == 80
        assert isinstance(record.body, ServerHello)

    def test_parse_certificate_request_in_handshake(self):
        certificate_request_packet = (
            b'\x01'  # certificate_types length
            b'\x01'  # certificate_types
            b'\x00\x02'  # supported_signature_algorithms length
            b'\x01'  # supported_signature_algorithms.hash
            b'\x01'  # supported_signature_algorithms.signature
            b'\x00\x00'  # certificate_authorities length
            b''  # certificate_authorities
        )

        handshake_packet = (
            b'\x0D'
            b'\x00\x00\x00\x08'
        ) + certificate_request_packet

        record = parse_handshake_struct(handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.CERTIFICATE_REQUEST
        assert record.length == 8
        assert isinstance(record.body, CertificateRequest)

    def test_parse_certificate_in_handshake(self):
        certificate_packet = (
            b'\x00\x00\x00\x07'  # certificate_length
            b'\x00\x00\x00\x03'  # certificate_list.asn1_cert length
            b'ABC'  # certificate_list.asn1_cert
        )

        handshake_packet = (
            b'\x0B'
            b'\x00\x00\x00\x0b'
        ) + certificate_packet

        record = parse_handshake_struct(handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.CERTIFICATE
        assert record.length == 11
        assert isinstance(record.body, Certificate)

    def test_parse_hello_request(self):
        handshake_packet = (
            b'\x00'
            b'\x00\x00\x00\x00'
            b''
        )
        record = parse_handshake_struct(handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.HELLO_REQUEST
        assert record.length == 0
        assert isinstance(record.body, HelloRequest)

    def test_server_hello_done(self):
        handshake_packet = (
            b'\x0E'
            b'\x00\x00\x00\x00'
            b''
        )
        record = parse_handshake_struct(handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.SERVER_HELLO_DONE
        assert record.length == 0
        assert isinstance(record.body, ServerHelloDone)

    def test_not_implemented(self):
        handshake_packet = (
            b'\x0C'
            b'\x00\x00\x00\x00'
            b''
        )
        record = parse_handshake_struct(handshake_packet)
        assert isinstance(record, Handshake)
        assert record.msg_type == HandshakeType.SERVER_KEY_EXCHANGE
        assert record.length == 0
        assert record.body is None
