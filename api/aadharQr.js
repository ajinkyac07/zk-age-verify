const zlib=require('zlib');
const crypto=require('crypto');
const fs=require('fs');

const FIELD_ORDER=[
    'emailMobileStatus',
    'referenceId',
    'name',
    'dob',
    'gender',
    'careOf',
    'district',
    'landmark',
    'house',
    'location',
    'pincode',
    'postOffice',
    'state',
    'street',
    'subDistrict',
    'vtc'
];

const DELIMITER=0xFF;
const SIGNATURE_LENGTH=256;
const HASH_LENGTH=32;
const VERSION_PATTERN=/^V[2-5]$/;

function base10ToByteArray(qrDataString){
    const big=BigInt(qrDataString);

    let hex=big.toString(16);

    if(hex.length%2!==0){
        hex='0'+hex;
    }

    let bytes=Buffer.from(hex,'hex');

    let attempts=0;

    while(
        !(bytes[0]===0x1f && bytes[1]===0x8b) &&
        attempts<4
    ){
        bytes=Buffer.concat([
            Buffer.from([0x00]),
            bytes
        ]);

        attempts++;
    }

    if(!(bytes[0]===0x1f && bytes[1]===0x8b)){
        throw new Error('QR payload is not a valid GZIP Secure QR payload');
    }

    return bytes;
}

function readField(data,start,fieldName){
    const end=data.indexOf(DELIMITER,start);

    if(end===-1){
        throw new Error(
            `Unexpected end of data while parsing field "${fieldName}"`
        );
    }

    return {
        value:data.slice(start,end).toString('latin1'),
        next:end+1
    };
}

function decodeSecureQR(qrDataString){
    if(typeof qrDataString!=='string'){
        throw new Error('QR data must be a string');
    }

    const qrData=qrDataString.replace(/\s+/g,'').trim();

    if(!/^\d+$/.test(qrData)){
        throw new Error('QR data must contain only digits');
    }

    const rawBytes=base10ToByteArray(qrData);
    const decompressed=zlib.gunzipSync(rawBytes);

    const totalLen=decompressed.length;

    if(totalLen<=SIGNATURE_LENGTH){
        throw new Error('QR payload is too short');
    }

    let idx=0;
    let version='V1';

    const fields={};

    // First field is either:
    // V2/V3/V4/V5 for newer QR versions
    // or the email/mobile status for V1.
    const first=readField(
        decompressed,
        idx,
        'version/status'
    );

    if(VERSION_PATTERN.test(first.value)){
        version=first.value;
        idx=first.next;

        const statusField=readField(
            decompressed,
            idx,
            'emailMobileStatus'
        );

        fields.emailMobileStatus=statusField.value;
        idx=statusField.next;
    }else{
        fields.emailMobileStatus=first.value;
        idx=first.next;
    }

    // Read remaining fields.
    const remainingFields=FIELD_ORDER.filter(
        field=>field!=='emailMobileStatus'
    );

    for(const fieldName of remainingFields){
        const field=readField(
            decompressed,
            idx,
            fieldName
        );

        fields[fieldName]=field.value;
        idx=field.next;
    }

    const photoStart=idx;

    // The final 256 bytes are the RSA signature.
    // For the current V2+ QR tested here, the signature
    // is stored in the order required directly by crypto.verify().
    const signatureStart=totalLen-SIGNATURE_LENGTH;

    if(signatureStart<=photoStart){
        throw new Error('Invalid QR signature boundary');
    }

    const signedData=decompressed.slice(
        0,
        signatureStart
    );

    const signature=Buffer.from(
        decompressed.slice(
            signatureStart,
            totalLen
        )
    );

    let photoEnd=signatureStart;

    let mobileHash=null;
    let emailHash=null;
    let last4Mobile=null;

    const status=parseInt(
        fields.emailMobileStatus,
        10
    );

    if(version==='V1'){
        if(status===3){
            mobileHash=Buffer.from(
                decompressed.slice(
                    photoEnd-HASH_LENGTH,
                    photoEnd
                )
            ).reverse();

            photoEnd-=HASH_LENGTH;

            emailHash=Buffer.from(
                decompressed.slice(
                    photoEnd-HASH_LENGTH,
                    photoEnd
                )
            ).reverse();

            photoEnd-=HASH_LENGTH;
        }else if(status===2){
            mobileHash=Buffer.from(
                decompressed.slice(
                    photoEnd-HASH_LENGTH,
                    photoEnd
                )
            ).reverse();

            photoEnd-=HASH_LENGTH;
        }else if(status===1){
            emailHash=Buffer.from(
                decompressed.slice(
                    photoEnd-HASH_LENGTH,
                    photoEnd
                )
            ).reverse();

            photoEnd-=HASH_LENGTH;
        }else if(status!==0){
            throw new Error(
                `Invalid email/mobile status: ${fields.emailMobileStatus}`
            );
        }
    }else{
        // V2-V5 append the last 4 mobile digits before the signature.
        if(photoEnd-photoStart<4){
            throw new Error(
                'Invalid V2-V5 QR: missing last-4-mobile field'
            );
        }

        const last4Start=photoEnd-4;

        last4Mobile=decompressed
            .slice(last4Start,photoEnd)
            .toString('latin1');

        photoEnd=last4Start;
    }

    const photo=decompressed.slice(
        photoStart,
        photoEnd
    );

    return {
        version,
        fields,
        photo,
        signature,
        signedData,
        mobileHash,
        emailHash,
        last4Mobile
    };
}

function verifySignature(
    signedData,
    signature,
    publicCertPath
){
    const cert=fs.readFileSync(
        publicCertPath
    );

    const verifier=crypto.createVerify(
        'RSA-SHA256'
    );

    verifier.update(signedData);
    verifier.end();

    return verifier.verify(
        cert,
        signature
    );
}

module.exports={
    decodeSecureQR,
    verifySignature
};