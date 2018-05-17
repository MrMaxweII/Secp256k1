import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.util.encoders.Hex;


	/****************************************************************************************
	 * 											*
	 * 	Zum Vergleich und zur Prüfung hier die Signatur von Bouncycastle 		*       
	 *											* 
	 ****************************************************************************************/


public class BouncycastleSig 
{
	

/**	Es wird eine Signatur erstellt bestehend aus den Teilen "r" und "s".
 *	Übergeben wird der 32byte lange Hash, der signiert werden soll,
 *	- der Priv.Key 32Byte,
 *	- die "rand" Zufallszahl als ByteArray.
 *	Rückgabe ist ein BigInteger-Array bestehend aus 2 Elementen: [0] = r   und    [1] = s. 
 *	Achtung: Die "rand" Zufallszahl muss aus einer kryptographisch starken Entropie stammen! 
 *	Falls "rand" vorhersehbar ist, kann der Priv.Key leicht aufgedeckt werden!!! */	
public static BigInteger[] sig(byte[] hash, byte[] priv, byte[] rand) 
{
	rand = Secp256k1.to_fixLength(rand,32);
	X9ECParameters p = SECNamedCurves.getByName("secp256k1");
	ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
	ECPrivateKeyParameters priKey 	= new ECPrivateKeyParameters(new BigInteger(1,priv), params);	
	SecureRandom k = new FixedSecureRandom(rand);   			   
	ECDSASigner dsa = new ECDSASigner();
	dsa.init(true, new ParametersWithRandom(priKey, k));
	BigInteger[] sig = dsa.generateSignature(hash);
	return sig;
}
	
	
	
/**	Die Signatur "r" und "s" wird geprüft. 
*	- Übergeben wird der 32byte lange Hash, dessen Signatur geprüft werden soll,
*	- die Signatur selbst "sig" als BigInteger-Array bestehend aus 2 Elementen: [0] = r   und    [1] = s. 
*	- und der Pub.Key als BigInteger Array mit 2 Elementen.*/
public static boolean verify(byte[] hash, BigInteger[] sig, BigInteger[] pub)
{			   
	X9ECParameters p = SECNamedCurves.getByName("secp256k1");
    	ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
	ECDSASigner dsa = new ECDSASigner();
    	ECPublicKeyParameters pubKey = new ECPublicKeyParameters(params.getCurve().decodePoint(Hex.decode("04" + pub[0].toString(16) + pub[1].toString(16) )), params); 
    	dsa.init(false, pubKey);
    	if (dsa.verifySignature(hash, sig[0], sig[1]))  return true;
    	else return false; 
}	
}


