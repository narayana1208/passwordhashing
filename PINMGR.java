
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class PINMGR 
{
	
	
	//class variables 
	private enum Adg{add,del,get};
	private static String masterkey="57a1b1eee3ab2ba14f6f5ae16f6899e7";
	private static  byte[] salt;
	private static  String[] Username=new String[10000];
	private static int iterations = 50000;
	private static String filepath="";
	
	
	
	public static void main(String[] args) throws IOException, GeneralSecurityException
	{
		int argsn=args.length;
	    File filedir=new File(System.getProperty("user.dir"));
	    File dirpath=new File(filedir,"pinmgr.txt");
	    filepath=dirpath.getPath();
		FileReader file=new FileReader(filepath);
		//@SuppressWarnings("resource")
		BufferedReader buff=new BufferedReader(file);
		PrintWriter printWriter = new PrintWriter (new FileWriter(filepath,true),false);
		if(argsn<3)
		{
			System.out.println("The number of arguments should be atleast 3");
			System.exit(0);
		}
		//password regular expression
		String pinpattern = "^(?=.*\\d)[\\d\\s]{4}$";
		Pattern r = Pattern.compile(pinpattern);
		PINMGR pinmgr =new PINMGR();
		//reading add||del||get from arg[0]
		String type=args[0];
		Adg adg=Adg.valueOf(type);
		//reading User name
		String username=args[1];
		//user name should be lower case
		int a=pinmgr.confirmlower(username);
		if(a!=0 || username.length()>128)
		{
			System.out.println("please check user name it should be in lower case or length should be less than 128");
			System.exit(0);
		}
		//reading password
		String password=args[2];
		//checking for printable ASCII lower
		boolean b=pinmgr.isAsciiPrintable(password);
		if (!b)
		{
			System.out.println("password should be printable ascii");
			System.exit(0);
		}
		String pinnum="";
		// switch case for add||get||del
		switch(adg)
		{
		 case add :
			 		//Case for adding user details
		        	System.out.println("ADD NEW USER DETAILS");
		        	if(argsn!=4)
		        	{
		        		System.out.println("No of arguments should be four");
		        		System.exit(0);
		        	}
		        	pinnum=args[3];
		        	//matching regular expression for pin
		        	Matcher matcher = r.matcher(pinnum);
		        	if (!matcher.matches()) 
		        	{
		        		System.out.println("Pin Number InValid");
		        		System.exit(0);
		        	}
		        	//looking for username details
		        	int suc=LookUp(username,buff);
		        	if(suc==0)
		        	{
		        	System.out.println("User NAME  ALREADY  EXITS "+suc);
		        	System.exit(0);
		        	}
		        	try 
		        	{
		        			String str=pinmgr.encryptUD(username,password,pinnum);
		        			System.out.println("writing to a file  "+str);
		        			printWriter.println (str);
		        			
		        	}
		        	catch (NoSuchAlgorithmException | InvalidKeySpecException e) 
		        	{
		        			// TODO Auto-generated catch block
		        				e.printStackTrace();
		        	}
		        	break;
		 case del :
		         	System.out.println("DELETING USER DETAILS");
		         	int del_status=1;
		         	if(argsn!=3)
		         	{
		         		System.out.println("provide username and password details");
		         		System.exit(0);
		         	}
		         	del_status=pinmgr.deleteUD(username,password,buff);
		         	if(del_status==0)
		         	{
		         		System.out.println("User Record is succesfully deleted");
		         	}
		         	else
		         	{
		         		System.out.println("User record is not deleted some error occured");
		         	}
		         	break;
		  case get :
		        	System.out.println("GETTING USER DETAILS");
		        	if(argsn!=3)
		        	{
		        		System.out.println("provide username and password details");
		        		System.exit(0);
		        	}
		        	pinmgr.retrievePIN(username,password,buff);
		        	break;
		  default :
		      		System.out.println("the arg[0] value should be one of add ,delete or get .");
		      		System.exit(0);
		}
		printWriter.close (); 
	}
	String  encryptUD(String user,String pass,String pin) throws GeneralSecurityException, UnsupportedEncodingException
	{
		System.out.println("USER DETAILS ARE BEING ADDED ");
		String generatedSecuredPasswordHash = generateStrongPasswordHash(pass);
		byte[] pinnum=encryptPin(pin);
		String Hex_encoder=new String(Hex.encode(pinnum));
		return user+":"+generatedSecuredPasswordHash+":"+Hex_encoder;
	}
	//@SuppressWarnings("null")
	private static int LookUp(String user,BufferedReader buf) throws IOException
	{
		String line="";
		int found=1;
		int i=0;
		while((line=buf.readLine() )!= null && i<10000)
    	{
			String[] columns=line.split(":");
			Username[i]=columns[0];
    		i++;
    	}
		for(int j=0;j<Username.length;j++)
		{
			if(user.equals(Username[j]))
			{
				found=0;
			}
		}
		if(found==0)
		{
			return 0;
		}
		else
		{
			return 1;
		}
	}

	private static byte[] encryptPin(String pinnum) throws GeneralSecurityException, NoSuchPaddingException
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		 cipher.init(
	                Cipher.ENCRYPT_MODE,
	                new SecretKeySpec(masterkey.getBytes(), "AES"),
	                new IvParameterSpec(salt));
		 byte[] result = null;
		 result=cipher.doFinal(pinnum.getBytes());
		return (result);
		
	}
	private static byte[] decryptPin(byte[] pinnumber) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(masterkey.getBytes(),"AES"),
                new IvParameterSpec(salt));
        byte[] pinresult=null;
        pinresult=cipher.doFinal(pinnumber);
		return pinresult;
	}
	private static String generateStrongPasswordHash(String password) throws GeneralSecurityException
    {
        salt = getSalt();
        byte[] PBKDF_Hash=PBKDF2(password,salt,iterations,256);
        return new String(Hex.encode(PBKDF_Hash))+ ":" +new String(Hex.encode(salt))+ ":" + iterations ;
    }
	private static byte[] PBKDF2(String  password, byte[] salt, int count, int n)throws GeneralSecurityException
	{
		char[] char_password = password.toCharArray();
		PBEKeySpec spec = new PBEKeySpec(char_password, salt, iterations, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
		return hash;
	}
    private static byte[] getSalt() throws GeneralSecurityException
    {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        byte[] hmac_salt=HMAC(salt);
        return hmac_salt;
    }
    //@SuppressWarnings("null")
	private static byte[] HMAC(byte[] h_salt) throws GeneralSecurityException
    {
    	byte[] salt_h = new byte[16];
    	SecretKeySpec signingKey = new SecretKeySpec(masterkey.getBytes(), "HmacSHA1");
    	Mac mac = Mac.getInstance("HmacSHA1");
    	mac.init(signingKey);
    	byte[] rawHmac = mac.doFinal(h_salt);
    	System.arraycopy(rawHmac, 0, salt_h, 0, 16);
    	return salt_h;
    }
	int deleteUD(String us,String pas,BufferedReader buffer) throws IOException, GeneralSecurityException
	{
		System.out.println("DELETING USER DETAILS");
		int success;
		 success=LookUp(us,buffer);
		 if(success==0)
 		{
 			System.out.println("USER DETAILS ARE BEING DELETED "+success);
 			
 		}
		try
		{
				File inFile = new File(filepath);
				System.out.println("file path "+inFile.getAbsolutePath());
				File tempFile = new File(inFile.getAbsolutePath()+".tmp");
				BufferedReader br = new BufferedReader(new FileReader(inFile));
				PrintWriter pw = new PrintWriter(new FileWriter(tempFile));
				String line = null;
				while ((line = br.readLine()) != null) 
				{
					  	String[] columns=line.split(":");
				        if (!columns[0].trim().equals(us)) 
						{
								pw.println(line);
								pw.flush();
						}
				        else
				        {
				        	int iterations=Integer.parseInt(columns[3]);
				        	byte[] password_hash=Hex.decode(columns[1]);
				        	String salt_str=columns[2];
							salt=Hex.decode(salt_str);
							boolean pass_hash_found=ValidatePassword(pas,iterations,salt,password_hash);
							if(pass_hash_found==false)
							{
								System.out.println("PASSWORD MISMATCH");
								System.exit(0);
							}
				        }
				}
				pw.close();
				br.close();
	        
				//Delete the original file
				if (!inFile.delete()) 
				{
					System.out.println("Could not delete file");
					return success+1;
				} 
	        
				//Rename the new file to the filename the original file had.
				if (!tempFile.renameTo(inFile))
					System.out.println("Could not rename file");
	        
	      }
	      catch (FileNotFoundException ex) 
	      {
	        ex.printStackTrace();
	      }
	      catch (IOException ex) 
	      {
	        ex.printStackTrace();
	      }
    		
		return success;
	}
	
	int retrievePIN(String use,String passwor,BufferedReader buffer) throws IOException, GeneralSecurityException
	{
			System.out.println("USER DETAILS ARE BEING RETRIEVED");
			int sucessget=LookUp(use,buffer);
			if (sucessget==1)
			{
				System.out.println("ERROR: UserName Does not exist");
				System.exit(0);
			}
			String line="";
			File inFile = new File(filepath);
			BufferedReader br = new BufferedReader(new FileReader(inFile));
			int flag=0;
			while((line=br.readLine() )!= null)
			{
				String[] columns=line.split(":");
				if (columns[0].trim().equals(use)) 
				{
					//String pin=columns[4];
					flag=1;
					int iterations=Integer.parseInt(columns[3]);
					byte[] password_hash=Hex.decode(columns[1]);
					String Hex_pin=columns[4];
					byte[] pinbyte=Hex.decode(Hex_pin);
					String salt_str=columns[2];
					salt=Hex.decode(salt_str);
					boolean pass_hash_found=false;
					pass_hash_found=ValidatePassword(passwor,iterations,salt,password_hash);
					if(pass_hash_found==false)
					{
						System.out.println("PASSWORD MISMATCH");
						System.exit(0);
					}
					byte[] pinnumber=decryptPin(pinbyte);
					String str=Hex.toHexString(pinnumber);
					int length=str.length();
					int j=0;
					int n=0;
						for(int i=0;i<length;i=i+2)
						{
							StringBuffer bu=new StringBuffer(2);
							
							while(j<2+i)
							{
								bu.append(str.charAt(j));
								j++;
							}
							n=Integer.parseInt(bu.toString(),16);
							System.out.print((char)n); 
						}
						System.exit(0);
				}
			}
			if(flag==0)
			{
				System.out.println("ERROR:USER NAME DOES NOT EXIST");
			}
			br.close();
			return 0;
		}
	private static boolean ValidatePassword(String UserPassword,int iterations,byte[] salt,byte[] StoredPasswordHash) throws GeneralSecurityException
	{
		byte[] User_Hash=PBKDF2(UserPassword,salt,iterations,256);
		int diff = StoredPasswordHash.length ^ User_Hash.length;
		
		for(int i = 0; i < StoredPasswordHash.length && i < User_Hash.length; i++)
		{
			diff |= StoredPasswordHash[i] ^ User_Hash[i];
		}
		
		return diff == 0;
		//return 0;
	}

	//to check whether the string is lower case
	int confirmlower(String usr)
	{
		final char[] chars = usr.toCharArray();
		for (int x = 0; x < chars.length; x++) 
		{      
			final char c = chars[x];
			if ((c >= 'a') && (c <= 'z')) continue;
			return 2;
		}  
		return 0;
	}

	//to check Non Printable ASCII characters
	boolean isAsciiPrintable(String pass)
	{
		if (pass == null) 
		{
			return false;
		}
		int sz = pass.length();
		char ch;
		for (int i = 0; i < sz; i++) 
		{
			ch=pass.charAt(i);
			if ((ch>= 32 && ch< 127) == false) 
				{
					return false;
				}
		}
		return true;
	}
}
