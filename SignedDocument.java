package signedDocument;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Certificate;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;
import com.itextpdf.signatures.PrivateKeySignature;

@SuppressWarnings({ "removal", "unused" })
public class SignedDocument {
	
	public static final String DEST = "./home/tb123/Desktop/PDF/signature.pdf";
	public static final String KEYSTORE = "./home/tb123/encryption/ks";
	public static final String SRC = "./home/tb123/Downloads/3864633108.pdf";
	
	 public static final char[] PASSWORD = "password".toCharArray();
	 
	 //public static final String[] RESULT_FILES = new String[] { "signed.pdf" };
	 
	 
	 public void sign(String src, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
	            String provider, PdfSigner.CryptoStandard signatureType, String reason, String location)
	            throws GeneralSecurityException, IOException {
		 
	        PdfReader reader = new PdfReader(src);
	        
	        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());
	 
	        // Create the signature appearance
	        Rectangle rect = new Rectangle(400,10,250,70);
	        
	        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
	         
	         appearance.setReason(reason);
	         appearance.setLocation(location);

            // Specify if the appearance before field is signed will be used
            // as a background for the signed field. The "false" value is the default value.
	         appearance.setReuseAppearance(false);
	         appearance.setPageRect(rect);
	         appearance.setPageNumber(1);
    signer.setFieldName("sig");
    
 // Creating the signature    
    BouncyCastleDigest digest = new BouncyCastleDigest();
    PrivateKeySignature signature = new PrivateKeySignature(pk, digestAlgorithm, provider);

    // Sign the document using the detached mode, CMS or CAdES equivalent.
    signer.signDetached(digest, signature, chain, null, null, null, 0, signatureType);
}

	 public static void main(String[] args) throws GeneralSecurityException, IOException {
	        File file = new File(DEST);
	        file.mkdirs();
	 
	        BouncyCastleProvider provider = new BouncyCastleProvider();
	        Security.addProvider(provider);
	        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
	        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
	        String alias = ks.aliases().nextElement();
	        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
	        Certificate[] chain = (Certificate[]) ks.getCertificateChain(alias);
	 
	        SignedDocument app = new SignedDocument();
	        
	        app.sign(SRC, String.format(DEST, 1), chain, pk, DigestAlgorithms.SHA256,
	        		provider.getName(), CryptoStandard.CMS, "Test 1", "Ghent");
	        	     				
	}

}
