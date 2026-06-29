# -*- coding: utf-8 -*-
#! /usr/bin/env python3
"""
A script to verify signed tables in ATSC 3.0 broacast according to ATSC A/360:2021

Usage:   python3 Tools/scripts/signatureVerify.py
"""
#import sys
import xml.etree.ElementTree as etree
from xml.dom import minidom
import base64
import binascii
import hashlib
import re

from datetime import datetime, timezone, timedelta
from asn1crypto import cms
from asn1crypto.ocsp import OCSPResponse
from cryptography import x509
from cryptography.x509 import DNSName
#from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def strip_ns(el):
    """Recursively remove namespaces from tags and attributes."""
    if '}' in el.tag:
        el.tag = el.tag.split('}', 1)[1]  # Strip "{namespace}"
    for key in list(el.attrib.keys()):
        if '}' in key:
            new_key = key.split('}', 1)[1]
            el.attrib[new_key] = el.attrib.pop(key)
    for child in el:
        strip_ns(child)

def verify_signature(child_cert, parent_cert):
    """Verifies that parent_cert signed child_cert."""
    public_key = parent_cert.public_key()
    
    # Extract signature and data details required for verification
    signature = child_cert.signature
    tbs_bytes = child_cert.tbs_certificate_bytes
    hash_algorithm = child_cert.signature_hash_algorithm
    
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                tbs_bytes,
                padding.PKCS1v15(),
                hash_algorithm
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature,
                tbs_bytes,
                ec.ECDSA(hash_algorithm)
            )
        else:
            raise TypeError("Unsupported public key type.")
        return True
    except Exception:
        return False

def verify_chain_without_root(leaf_pem, intermediate_pems):
    """
    Validates a list of PEM certificate strings from leaf to the top intermediate.
    intermediate_pems should be ordered: [Immediate CA, Parent CA, Top Intermediate CA...]
    """
    #leaf = x509.load_pem_x509_certificate(leaf_pem.encode())
    #chain = [leaf] + [x509.load_pem_x509_certificate(cert.encode()) for cert in intermediate_pems]
    chain = [leaf_pem] + [intermediate_pems]
    
    for i in range(len(chain) - 1):
        child = chain[i]
        parent = chain[i + 1]
        
        # 1. Verify Issuer name matches Subject name of parent
        if child.issuer != parent.subject:
            print(f"Broken Chain: Issuer of Cert {i} does not match Subject of Cert {i+1}")
            return False
            
        # 2. Cryptographically verify the signature
        if not verify_signature(child, parent):
            print(f"Invalid Signature: Cert {i} was not signed by Cert {i+1}")
            return False
            
        print(f"Link {i} verified: '{child.subject.rfc4514_string()}' signed by '{parent.subject.rfc4514_string()}'")
    
    #print("Success: Every certificate in the partial chain is structurally valid!")
    return True
    
#######################
# MAIN PROGRAM
#######################

if __name__ == "__main__":
    
    retval = 0
    
    # Load and parse the XML file
    try:
        tree = etree.parse('CDT.xml')
        root = tree.getroot()
    except FileNotFoundError:
        retval = 254
        exit(str(retval))
    except PermissionError:
        retval = 253
        exit(str(retval))
    except Exception as e:
        retval = 252
        exit(str(retval))
    
    # Find specific elements  
    #print(root[0][0].text)
    #print(root[0][1].text)
    #print(root[0][2].text)
    begin = "-----BEGIN CERTIFICATE-----\n"
    end = "\n-----END CERTIFICATE-----"
    # Save the leaf cert to a file
    with open("intermediate.pem", "wb") as f:
        cert = (root[0][1].text).encode('utf-8')
        f.write(begin.encode('utf-8'))
        f.write(cert)
        f.write(end.encode('utf-8'))
    # Save the intermediate cert to a file
    with open("leafSMT.pem", "wb") as f:
        cert = (root[0][0].text).encode('utf-8')
        f.write(begin.encode('utf-8'))
        f.write(cert)
        f.write(end.encode('utf-8'))
    # Save the root cert to a file
    with open("leafCDT.pem", "wb") as f:
        cert = (root[0][2].text).encode('utf-8')
        f.write(begin.encode('utf-8'))
        f.write(cert)
        f.write(end.encode('utf-8'))
    
    # Remove namespace from the tags in root[0] (ToBeSignedData)
    strip_ns(root[0])
    
    
    #####  CDT VERIFICATION #######
    # Load OCSP Response (if available) 
    # 1. Strip the PEM headers, footers, and any whitespace
    try:
        pem_lines = (root[4].text).strip().split('\n')
    except:
        pem_lines = (root[3].text).strip().split('\n')
    
    der_base64 = "".join([line for line in pem_lines if not line.startswith("-----")])
    
    # 2. Decode the base64 string to DER binary
    der_bytes = base64.b64decode(der_base64)
    
    # 3. Load the DER bytes into an OCSPResponse object
    #ocsp_response = ocsp.load_der_ocsp_response(der_bytes)
    #print(f"[*] OCSP Response Status: {ocsp_response.response_status}")
    parsed = OCSPResponse.load(der_bytes)
    
    # Access all individual single responses in the array
    single_responses = parsed['response_bytes']['response'].native['tbs_response_data']['responses']
    
    
#    # 4. Verify the response status
#    if ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
#        # 5. Extract OCSP Information
#        for single_response in ocsp_response.responses:
#            if (single_response.certificate_status == ocsp.OCSPCertStatus.GOOD):
#                print(f"CDT certificate status GOOD.")
#            else:
#                print(f"CDT certificate status: {single_response.certificate_status}")
#            #print(f"[CDT Cert*] Certificate Serial: {single_response.serial_number}")
#            #print(f"[CDT Cert*] Revocation Status: {single_response.certificate_status}")
#            print(f"[CDT Cert*] This Update: {single_response.this_update_utc}")
#            print(f"[CDT Cert*] Next Update: {single_response.next_update_utc}")
#            #print(f"[CDT Cert*] Key hash: {single_response.issuer_key_hash}")
#            #print(f"[CDT Cert*] Name hash: {single_response.issuer_name_hash}")
#            #print(f"[CDT Cert*] Hash alg: {single_response.hash_algorithm}")
#            if single_response.revocation_time_utc:
#                print(f"[CDT Cert*] Revoked at: {single_response.revocation_time_utc}")
#                print(f"[CDT Cert*] Revoked reason: {single_response.revocation_reason}")
#    else:
#        print(f"[CDT Cert*] OCSP failed with status: {ocsp_response.response_status}")
    
    for single_response in single_responses:
        cert_id = single_response['cert_id']
        if (single_response['cert_status'] == 'good'):
            print(f"CDT certificate status GOOD.")
        elif (single_response['cert_status'] == 'revoked'):
            print(f"CDT certificate status REVOKED.")
            print(f"[CDT Cert*] Revoked at: {single_response['cert_status'].native['revocation_time']}")
            print(f"[CDT Cert*] Revoked reason: {single_response['cert_status'].native['revocation_reason']}")
        else:
            print(f"CDT certificate status: {single_response['cert_status']}")
        #print(f"[CDT Cert*] Certificate Serial: {single_response.serial_number}")
        #print(f"[CDT Cert*] Revocation Status: {single_response.certificate_status}")
        print(f"[CDT Cert*] This Update: {single_response['this_update']}")
        print(f"[CDT Cert*] Next Update: {single_response['next_update']}")
        #print(f"[CDT Cert*] Key hash: {single_response.issuer_key_hash}")
        #print(f"[CDT Cert*] Name hash: {single_response.issuer_name_hash}")
        #print(f"[CDT Cert*] Hash alg: {single_response.hash_algorithm}")
    
    ocspRefresh = root[0].attrib['OCSPRefresh']
    # Regex to capture digits preceding 'D' and 'H'
    match = re.match(r"P(?:(\d+)D)?T(?:(\d+)H)?", ocspRefresh)
    
    days, hours = match.groups()
    days=int(days) if days else 0
    # Convert captured strings to integers (defaulting to 0 if absent)
    duration = timedelta(
        days=int(days) if days else 0,
        hours=int(hours) if hours else 0
    )
    days = (int(days) * 24)
    hours = days + int(hours)
    #print(single_response.this_update_utc + duration)
    #if hours < 240 and (single_response.this_update_utc + duration) > datetime.now(timezone.utc) :
    if hours < 240 and (single_response['this_update'] + duration) > datetime.now(timezone.utc) :
        print(f"CDT OCSP Refresh < 10days within current time.")
    else:
        print(f"CDT OCSP Refresh > 10days from current time.")
        retval = 251 # Signature is old
    
    
    # Check the certificate chain
    with open("leafCDT.pem", "rb") as f:
        leafCDT = x509.load_pem_x509_certificate(f.read())
    
    with open("intermediate.pem", "rb") as f:
        intermediate = x509.load_pem_x509_certificate(f.read())
    
    #with open(root_path, "rb") as f:
    #    root = x509.load_pem_x509_certificate(f.read())
    
    verify_chain_without_root(leafCDT, intermediate)
    
    
    
    
    #####  CDT VERIFICATION #######
    # Extract the public key object
    cdt_public_key = leafCDT.public_key()
    
    # Extract the message
    #message = etree.tostring(root[0], encoding='utf-8')
    message = etree.tostring(root[0])
    message = message.decode('utf-8')
    message = message.rstrip() # removes trailing newlines and whitespace
    #message = message.rstrip('\n') # Removes only trailing newline characters specifically
    msg = base64.b64decode(message)
    message = message.encode('utf-8')
    #print(message)
    
    # Extract the signature from RFC5652: CMS Signed Data Structure of the CDT
    for elem in root.iter():
        if (elem.tag == '{tag:atsc.org,2016:XMLSchemas/ATSC3/Delivery/CDT/1.0/}CMSSignedData'):
            cms_content = bytes(elem.text.encode('utf-8')) # i.e., root[1].text
            
            # Load the ContentInfo structure (the root of a CMS message)
            cmsData = base64.b64decode(cms_content)
            content_info = cms.ContentInfo.load(cmsData)
            
            # Access the specific type (e.g., 'signed_data')
            signed_data = content_info['content']
            signer_info = signed_data['signer_infos'][0]
            try:
                sid = signer_info['sid']
                C = sid.native['issuer']['country_name']
                O = sid.native['issuer']['organization_name']
                OU = sid.native['issuer']['organizational_unit_name']
                CN = sid.native['issuer']['common_name']
                Ser = sid.native['serial_number']
                #print(sid.native)
                #print(signed_data.native)
                #print(signer_info)
                print(f'CMS\tO: {O}\n\tOU: {OU}\n\tCN: {CN}')
                #print(f'CMS Serial#: {Ser}')
            except:
                pass  # Some certificates might not populate all fields
            
            # extract the remaining components
            signature = signer_info['signature'].native
            
            # Test hash in the signature
            recovered_data = cdt_public_key.recover_data_from_signature(
                signer_info['signature'].native,
                padding.PKCS1v15(),
                None # Must be None for data recovery
            )
            
            signature_algorithm = signer_info['signature_algorithm']['algorithm'].native
            hash_algorithm = signer_info['digest_algorithm']['algorithm'].native
            signed_attrs = signer_info['signed_attrs']
            signed_attrs_der = signer_info['signed_attrs'].dump()
            # tolerate some library errors tagging signedAttr as IMPLICIT (0xA0) and not SET OF (0x31)
            if signed_attrs_der[0] == 0xA0:
                signed_attrs_der = bytes([0x31]) + signed_attrs_der[1:]
            elif signed_attrs_der[0] == 0x31:
                pass #correct library used
            else:
                print(f'signed_attrs tag {signed_attrs_der[0]} is wrong.')
            
            # Take hash of signed attributes
            signed_attrs_hash = hashlib.sha512(signed_attrs_der).hexdigest()
            
            for signed_attr in signed_attrs:
            # if using Python 3.10 and above, can use 'match' case statement
            #    match signed_attr['type'].native:
            #        case 'message_digest':
            #            payload_hash = signed_attr['values'][0].native
            #        case 'signing_time':
            #            signature_timestamp = signed_attr['values'][0].native
            # else use Python 3.9 if case statement
                if signed_attr['type'].native == 'message_digest':
                    payload_hash = signed_attr['values'][0].native
                    payload_hash = (binascii.b2a_hex(payload_hash)).decode('utf-8')
                if signed_attr['type'].native == 'signing_time':
                    signature_timestamp = signed_attr['values'][0].native
                    print(f'CDT Signature Time: {signature_timestamp}')
                    # Verify Signature Time
                    try:
                        if (signature_timestamp <= datetime.now(timezone.utc)):
                            print(f"The CDT Signature Time is valid.")
                        else:
                            print(f"The CDT Signature Time has expired.")
                    except Exception as e:
                        print(f"The CDT signature Time is invalid. {e}")
                    
            print(f'CDT Payload Hash: {payload_hash}')
            
            # Take our own hash across the message to compare results and verify message is correct
            if hash_algorithm == 'sha256':
                hash_result = hashlib.sha256(message).hexdigest()
                print(f'Local SHA256 Hash {hash_result}')
                hash_digest = recovered_data[-32:]
                print(f'Signature Hash:   {hash_digest.hex()}')
            elif hash_algorithm == 'sha384':
                hash_result = hashlib.sha384(message).hexdigest()
                print(f'Local SHA384 Hash {hash_result}')
                hash_digest = recovered_data[-48:]
                print(f'Signature Hash:   {hash_digest.hex()}')
            elif hash_algorithm == 'sha512':
                hash_result = hashlib.sha512(message).hexdigest()
                print(f'Local SHA512 Hash {hash_result}')
                hash_digest = recovered_data[-64:]
                print(f'Signature Hash:   {hash_digest.hex()}')
            else:
                print(f'CMS Invalid Hash: {hash_result}')
            
            print(f'CMS Signed Hash:  {signed_attrs_hash}')
            #print(f'CMS Payload Signature: {signature}')
            #print(f'CMS Payload Sign ALG: {signature_algorithm}')
            #print(f'CMS Payload Hash ALG: {hash_algorithm}')
            
    # Verify the signature
    try:
        if hash_algorithm == 'sha256':
            cdt_public_key.verify(
                signature,
                signed_attrs_der,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("The CDT signature is valid.\n")
        elif hash_algorithm == 'sha384':
            cdt_public_key.verify(
                signature,
                signed_attrs_der,
                padding.PKCS1v15(),
                hashes.SHA384()
            )
            print("The CDT signature is valid.\n")
        elif hash_algorithm == 'sha512':
            cdt_public_key.verify(
                signature,
                signed_attrs_der,
                padding.PKCS1v15(),
                hashes.SHA512()
            )
            print("The CDT signature is valid.\n")
        else:
            print("Unsupported CDT signature algorithm.\n")
            retval = 100 # signature is invalid
    except Exception as e:
        print(f"The CDT signature is invalid. {e}\n")
        retval = 100 # signature is invalid
    
    
    
    
    
    
    
    #####  SMT VERIFICATION #######
    # Load OCSP Response 
    # 1. Strip the PEM headers, footers, and any whitespace
    pem_lines = (root[2].text).strip().split('\n')
    der_base64 = "".join([line for line in pem_lines if not line.startswith("-----")])
    
    # 2. Decode the base64 string to DER binary
    der_bytes = base64.b64decode(der_base64)
    
    # 3. Load the DER bytes into an OCSPResponse object
    #ocsp_response = ocsp.load_der_ocsp_response(der_bytes)
    #print(f"[*] OCSP Response Status: {ocsp_response.response_status}")
    parsed = OCSPResponse.load(der_bytes)
    
    # Access all individual single responses in the array
    single_responses = parsed['response_bytes']['response'].native['tbs_response_data']['responses']
    
    # 4. Verify the response status
    #if ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
    #    # 5. Extract OCSP Information
    #    for single_response in ocsp_response.responses:
    #        if (single_response.certificate_status == ocsp.OCSPCertStatus.GOOD):
    #            print(f"SMT certificate status GOOD.")
    #        else:
    #            print(f"SMT certificate status: {single_response.certificate_status}")
    #        #print(f"[SMT Cert*] Certificate Serial: {single_response.serial_number}")
    #        #print(f"[SMT Cert*] Revocation Status: {single_response.certificate_status}")
    #        print(f"[SMT Cert*] This Update: {single_response.this_update_utc}")
    #        print(f"[SMT Cert*] Next Update: {single_response.next_update_utc}")
    #        #print(f"[SMT Cert*] Key hash: {single_response.issuer_key_hash}")
    #        #print(f"[SMT Cert*] Name hash: {single_response.issuer_name_hash}")
    #        #print(f"[SMT Cert*] Hash alg: {single_response.hash_algorithm}")
    #        if single_response.revocation_time_utc:
    #            print(f"[SMT Cert*] Revoked at: {single_response.revocation_time_utc}")
    #            print(f"[SMT Cert*] Revoked reason: {single_response.revocation_reason}")
    #else:
    #    print(f"[SMT Cert*] OCSP failed with status: {ocsp_response.response_status}")
    
    for single_response in single_responses:
        cert_id = single_response['cert_id']
        if (single_response['cert_status'] == 'good'):
            print(f"SMT certificate status GOOD.")
        elif (single_response['cert_status'] == 'revoked'):
            print(f"SMT certificate status REVOKED.")
            print(f"[SMT Cert*] Revoked at: {single_response['cert_status'].native['revocation_time']}")
            print(f"[SMT Cert*] Revoked reason: {single_response['cert_status'].native['revocation_reason']}")
        else:
            print(f"SMT certificate status: {single_response['cert_status']}")
        #print(f"[SMT Cert*] Certificate Serial: {single_response.serial_number}")
        #print(f"[SMT Cert*] Revocation Status: {single_response.certificate_status}")
        print(f"[SMT Cert*] This Update: {single_response['this_update']}")
        print(f"[SMT Cert*] Next Update: {single_response['next_update']}")
        #print(f"[SMT Cert*] Key hash: {single_response.issuer_key_hash}")
        #print(f"[SMT Cert*] Name hash: {single_response.issuer_name_hash}")
        #print(f"[SMT Cert*] Hash alg: {single_response.hash_algorithm}")
    
    ocspRefresh = root[0].attrib['OCSPRefresh']
    # Regex to capture digits preceding 'D' and 'H'
    match = re.match(r"P(?:(\d+)D)?T(?:(\d+)H)?", ocspRefresh)
    
    days, hours = match.groups()
    days=int(days) if days else 0
    # Convert captured strings to integers (defaulting to 0 if absent)
    duration = timedelta(
        days=int(days) if days else 0,
        hours=int(hours) if hours else 0
    )
    days = (int(days) * 24)
    hours = days + int(hours)
    #if hours < 240 and (single_response.this_update_utc + duration) > datetime.now(timezone.utc) :
    if hours < 240 and (single_response['this_update'] + duration) > datetime.now(timezone.utc) :
        print(f"SMT OCSP Refresh < 10days within current time.")
    else:
        print(f"SMT OCSP Refresh > 10days from current time.")
        retval = 250 # Signature is old
    
    
    # Check the certificate chain
    # Read certificates from files
    with open("leafSMT.pem", "rb") as f:
        leafSMT = x509.load_pem_x509_certificate(f.read())
    
    verify_chain_without_root(leafSMT, intermediate)
    
    currentCert = root[0][3].text # SubjectKeyIdentifier for cert used to sign signaling messages
    currentCertb = base64.b64decode(currentCert)
    currentCert_hex = ":".join("{:02X}".format(b) for b in currentCertb)
    #print(f"Current Cert Subject KeyID: {currentCert_hex}\n")    
    
    #####  SMT VERIFICATION #######    
    # Parse the certificate
    try:    
        print(leafSMT.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value)
        print(leafSMT.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value)
        print(leafSMT.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value)
        print(leafSMT.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
    except:
        pass # Some certs might not have all fields
    
    # Extract the public key object
    smt_public_key = leafSMT.public_key()
    
    # Get the Subject Key Identifier extension
    try:
        # OID for Subject Key Identifier is 2.5.29.14
        ski_extension = leafSMT.extensions.get_extension_for_oid(x509.OID_SUBJECT_KEY_IDENTIFIER)
        
        # Access the raw digest (bytes)
        ski_digest = ski_extension.value.digest
        
        # Format as a colon-separated hex string (common format)
        ski_hex = ":".join("{:02X}".format(b) for b in ski_digest)
        
        if ski_hex == currentCert_hex:
            print(f"SMT Subject Key Identifier: {ski_hex} matches current cert")
        else:
            print(f"SMT Subject Key Identifier: {ski_hex} does not match current cert")
    except x509.ExtensionNotFound:
        print("This SMT certificate does not have a Subject Key Identifier extension.")
        
    
    # Get the Extended Key Usage
    try:        
        #OID for Subject Directory Attributes is 2.5.29.9 shall include attribute for 
        # id-atsc-sdattr-bsid = id-atsc.9.1 = 1.3.6.1.4.1.51552.9.1
        sda_extension = leafSMT.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES)
        
        # Access the values
        #sda_oid = sda_extension.value.oid
        sda_value = sda_extension.value.value # DER-encoded bytes of extension
        
        sda_bsid = base64.b64decode(sda_value)
        #sda_bsid = set(sda_bsid)
        print(f"SMT BSIDs: {sda_bsid}")
        
        #EKU for id-atsc-kp-signalingSinging is id-atsc.37.3 = 1.3.6.1.4.1.51552.37.3
        eku_extension = leafSMT.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        eku_values = eku_extension.value
        
        # Print the OID numbers and names
        for usage in eku_values:
            if usage.dotted_string == '1.3.6.1.4.1.51552.37.3':
               print(f"SMT EKU: {usage.dotted_string} is for signaling signing")
            else:
               print(f"SMT EKU: {usage.dotted_string} is not for signaling signing")
            
        
    except x509.ExtensionNotFound:
        print("This SMT certificate does not have proper Extended Key Usage values.")
    
    # Extract the signature from RFC5652: CMS Signed Data Structure of the SMT
    with open("CMS.bin", "rb") as cert_file:
        cmsSign = cert_file.read()
    
    # Load the ContentInfo structure (the root of a CMS message)
    content_info = cms.ContentInfo.load(cmsSign)
    
    # Access the specific type (e.g., 'signed_data')
    signed_data = content_info['content']
    signer_info = signed_data['signer_infos'][0]
    
    try:
        sid = signer_info['sid']
        C = sid.native['issuer']['country_name']
        O = sid.native['issuer']['organization_name']
        OU = sid.native['issuer']['organizational_unit_name']
        CN = sid.native['issuer']['common_name']
        Ser = sid.native['serial_number']
        #print(sid.native)
        #print(signed_data.native)
        #print(signer_info)
        print(f'CMS O: {O}\n\tOU: {OU}\n\tCN: {CN}')
        print(f'CMS Serial#: {Ser}')
    except:
        pass # Some certificates might not populate all fields
    
    # OPTIONAL if CMS contains certificates (not default)
    cert_obj = None
    for cert in signed_data['certificates']:
        print('\ncertificates')
        if (cert.chosen.issuer == sid.native['issuer'] and 
            cert.chosen.serial_number == sid.native['serial_number']):
            # Load certificate using cryptography
            cert_obj = x509.load_der_x509_certificate(cert.chosen.dump())
            break
    # Extract public key
    if cert_obj:
        smt_public_key = cert_obj.public_key()
        print("Public key extracted successfully.")
    
    # Extract the message
    with open("SMT.bin", "rb") as smt_file:
        message = smt_file.read()
    
    message = message.rstrip() # removes trailing newlines and whitespace
    #message = message.rstrip('\n') # Removes only trailing newline characters specifically
    msg = base64.b64decode(message)
    
    # extract the remaining components
    signature = signer_info['signature'].native
    
    # Test hash in the signature
    recovered_data = smt_public_key.recover_data_from_signature(
        signer_info['signature'].native,
        padding.PKCS1v15(),
        None # Must be None for data recovery
    )
    
    signature_algorithm = signer_info['signature_algorithm']['algorithm'].native
    hash_algorithm = signer_info['digest_algorithm']['algorithm'].native
    
    # Access the specific type (e.g., 'signed_data')
    signed_data = content_info['content']
    signer_info = signed_data['signer_infos'][0]
    
    signed_attrs = signer_info['signed_attrs']
    signed_attrs_der = signer_info['signed_attrs'].dump()
    # tolerate some library errors tagging signedAttr as IMPLICIT (0xA0) and not SET OF (0x31)
    if signed_attrs_der[0] == 0xA0:
        signed_attrs_der = bytes([0x31]) + signed_attrs_der[1:]
    elif signed_attrs_der[0] == 0x31:
        pass #correct library used
    else:
        print(f'signed_attrs tag {signed_attrs_der[0]} is wrong.')
    
    # Take hash of signed attributes
    signed_attrs_hash = hashlib.sha512(signed_attrs_der).hexdigest()
    
    for signed_attr in signed_attrs:
    # if using Python 3.10 and above, can use 'match' case statement
    #    match signed_attr['type'].native:
    #        case 'message_digest':
    #            payload_hash = signed_attr['values'][0].native
    #        case 'signing_time':
    #            signature_timestamp = signed_attr['values'][0].native
    # else use Python 3.9 if case statement
        if signed_attr['type'].native == 'message_digest':
            payload_hash = signed_attr['values'][0].native
            payload_hash = (binascii.b2a_hex(payload_hash)).decode('utf-8')
        if signed_attr['type'].native == 'signing_time':
            signature_timestamp = signed_attr['values'][0].native
            print(f'SMT Signature Time: {signature_timestamp}')
            # Verify Signature Time
            try:
                if (signature_timestamp <= datetime.now(timezone.utc)):
                    print(f"The SMT Signature Time is valid.\n")
                else:
                    print(f"The SMT Signature Time has expired.\n")
            except Exception as e:
                print(f"The SMT signature Time is invalid. {e}\n")
                
    print(f'SMT Payload Hash: {payload_hash}')
    
    # Take our own hash across the message to compare results and verify message is correct
    if hash_algorithm == 'sha256':
        hash_result = hashlib.sha256(message).hexdigest()
        print(f'Local SHA256 Hash {hash_result}')
        hash_digest = recovered_data[-32:]
        print(f'Signature Hash:   {hash_digest.hex()}')
    elif hash_algorithm == 'sha384':
        hash_result = hashlib.sha384(message).hexdigest()
        print(f'Local SHA384 Hash {hash_result}')
        hash_digest = recovered_data[-48:]
        print(f'Signature Hash:   {hash_digest.hex()}')
    elif hash_algorithm == 'sha512':
        hash_result = hashlib.sha512(message).hexdigest()
        print(f'Local SHA512 Hash {hash_result}')
        hash_digest = recovered_data[-64:]
        print(f'Signature Hash:   {hash_digest.hex()}')
    else:
        print(f'CMS Invalid Hash: {hash_result}')
        
    print(f'CMS Signed Hash:  {signed_attrs_hash}')
    #print(f'CMS Payload Signature: {signature}')
    #print(f'CMS Payload Sign ALG: {signature_algorithm}')
    #print(f'CMS Payload Hash ALG: {hash_algorithm}')
    
    # Verify the signature
    try:
        if hash_algorithm == 'sha256':
            smt_public_key.verify(
                signature,
                signed_attrs_der,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("The SMT signature is valid.\n")
        elif hash_algorithm == 'sha384':
            smt_public_key.verify(
                signature,
                signed_attrs_der,
                padding.PKCS1v15(),
                hashes.SHA384()
            )
            print("The SMT signature is valid.\n")
        elif hash_algorithm == 'sha512':
            smt_public_key.verify(
                signature,
                signed_attrs_der,
                padding.PKCS1v15(),
                hashes.SHA512()
            )
            print("The SMT signature is valid.\n")
        else:
            print("Unsupported SMT signature algorithm.\n")
            retval = 100 # signature is invalid
    except Exception as e:
        print(f"The SMT signature is invalid. {e}\n")
        retval = 100 # signature is invalid
        
    
    
    exit(str(retval))
    