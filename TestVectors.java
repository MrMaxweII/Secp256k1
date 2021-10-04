package ECDSA;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
import org.json.JSONObject;


/***********************************************************************************************
*	Version 1.0 Autor: Mr. Maxwell	vom 04.10.2021											*
*	Hier werden Testvektoren im JSON Format ausgegeben.										*
*	Die Testvektoren sind das Ergebnis einer ECC-Multiplikation auf der secp256k1 Kurve.	*
************************************************************************************************/


public class TestVectors 
{
	public static void main(String[] args) throws Exception
	{	
		System.out.println("ECC Multiplication Test Vectors SECP256K1\nVersion 1.0\nEnter the number of test vectors: "); 
		Scanner sc = new Scanner(System.in); 

		int z  = sc.nextInt(); // Anzahl der Testvektoren die ausgegeben werden	2	
		sc.close();
		JSONObject jo = new JSONObject();
		for(int i=0;i<z;i++)
		{		
			byte[] p = Calc.getHashSHA256((new BigInteger(256, new Random())).toByteArray());		
			String str_p = Convert.byteArrayToHexString(p);
			String pubX = Calc.getPublicKeyX(str_p);
			String pubY = Calc.getPublicKeyY(str_p);
			JSONObject joA = new JSONObject();
			joA.put("p", str_p);
			joA.put("x", pubX);
			joA.put("y", pubY);
			jo.put(String.valueOf(i),joA);			
		}
		String fileName = "vektors.JSON";
		BufferedWriter br = new BufferedWriter(new FileWriter(fileName));
		br.write(jo.toString(1));
		br.close();
		System.out.println("File "+fileName+" with "+z+" elements has been created.");
	}
}