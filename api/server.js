const express=require('express');
const cors=require('cors');
const {buildPoseidon}=require('circomlibjs');
const snarkjs=require('snarkjs');
const crypto=require('crypto');
const fs=require('fs');
const path=require('path');
const {decodeSecureQR}=require('./aadharQr');

const app=express();

app.use(cors());
app.use(express.json({limit:'50kb'}));
app.use(express.static(path.join(__dirname,'public')));

const PORT=3000;

const UIDAI_CERT_PATH=path.join(
    __dirname,
    'certs',
    'uidai_offline_publickey_2026.cer'
);

const UIDAI_CERT=fs.readFileSync(UIDAI_CERT_PATH);
const UIDAI_X509=new crypto.X509Certificate(UIDAI_CERT);

let poseidonInstance=null;

async function getPoseidon(){
    if(!poseidonInstance){
        poseidonInstance=await buildPoseidon();
    }

    return poseidonInstance;
}

function normalizeDob(dob){
    const value=String(dob).trim();

    if(/^\d{8}$/.test(value)){
        const year=value.slice(0,4);
        const month=value.slice(4,6);
        const day=value.slice(6,8);

        validateDate(year,month,day);

        return value;
    }

    const match=value.match(/^(\d{2})[-/](\d{2})[-/](\d{4})$/);

    if(!match){
        throw new Error('Unsupported DOB format');
    }

    const day=match[1];
    const month=match[2];
    const year=match[3];

    validateDate(year,month,day);

    return year+month+day;
}

function validateDate(year,month,day){
    const y=Number(year);
    const m=Number(month);
    const d=Number(day);

    const date=new Date(Date.UTC(y,m-1,d));

    if(
        date.getUTCFullYear()!==y ||
        date.getUTCMonth()!==m-1 ||
        date.getUTCDate()!==d
    ){
        throw new Error('Invalid DOB');
    }
}

async function createCredential(dob){
    const poseidon=await getPoseidon();

    const salt=BigInt(
        '0x'+crypto.randomBytes(8).toString('hex')
    );

    const dobValue=BigInt(normalizeDob(dob));

    const hash=poseidon([dobValue,salt]);

    const commitment=poseidon.F.toString(hash);

    return {
        commitment,
        salt:salt.toString(),
        dob:dobValue.toString()
    };
}

function verifyUidaiSignature(signedData,signature){
    return crypto.verify(
        'RSA-SHA256',
        signedData,
        UIDAI_X509.publicKey,
        signature
    );
}

function cleanQrData(qrData){
    if(typeof qrData!=='string'){
        throw new Error('qrData must be a string');
    }

    const cleaned=qrData.replace(/\s+/g,'').trim();

    if(!cleaned){
        throw new Error('qrData is empty');
    }

    if(!/^\d+$/.test(cleaned)){
        throw new Error('qrData must contain only digits');
    }

    if(cleaned.length>10000){
        throw new Error('qrData is too large');
    }

    return cleaned;
}


// 1. ISSUE CREDENTIAL
app.post('/issue-credential',async(req,res)=>{
    try{
        const {dob}=req.body;

        const credential=await createCredential(dob);

        res.json({
            commitment:credential.commitment,
            salt:credential.salt
        });
    }
    catch(error){
        res.status(400).json({
            error:error.message
        });
    }
});


// 2. VERIFY AADHAAR SECURE QR
app.post('/verify-aadhaar-qr',async(req,res)=>{
    try{
        const qrData=cleanQrData(req.body.qrData);

        const decoded=decodeSecureQR(qrData);

        const signatureValid=verifyUidaiSignature(
            decoded.signedData,
            decoded.signature
        );

        if(!signatureValid){
            return res.status(400).json({
                verified:false,
                message:'UIDAI Secure QR signature verification failed'
            });
        }

        const dob=normalizeDob(decoded.fields.dob);

        const credential=await createCredential(dob);

        res.json({
            verified:true,
            source:'UIDAI Secure QR',
            message:'UIDAI signature verified. Credential issued.',

            credential:{
                commitment:credential.commitment,
                salt:credential.salt,
                dob:credential.dob
            }
        });
    }
    catch(error){
        res.status(400).json({
            verified:false,
            error:error.message
        });
    }
});


// 3. VERIFY ZK PROOF
app.post('/verify-proof',async(req,res)=>{
    try{
        const {proof,publicSignals}=req.body;

        const vKey=JSON.parse(
            fs.readFileSync(
                path.join(__dirname,'verification_key.json')
            )
        );

        const isValid=await snarkjs.groth16.verify(
            vKey,
            publicSignals,
            proof
        );

        if(isValid){
            res.json({
                verified:true,
                age_over_18:true,
                message:'Valid Proof! DOB was kept secret.'
            });
        }
        else{
            res.status(400).json({
                verified:false,
                message:'Invalid Proof.'
            });
        }
    }
    catch(error){
        res.status(500).json({
            error:error.message
        });
    }
});


app.listen(PORT,'0.0.0.0',()=>{
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('UIDAI certificate:',UIDAI_X509.subject);
    console.log('UIDAI certificate valid to:',UIDAI_X509.validTo);
});