import java.io.*;
import java.lang.*;
import java.util.*;

public class DictionaryParser
{
	FileInputStream FileDscr;
	static Vector FileName = new Vector();
	static String Path;
	static Hashtable hash;

        String TmpCode, TmpType;
        int TmpValeur;
        Hashtable attributes = null;
        Hashtable values = null;

	/**
	The constructor tries to open file with the specified
	name. The application is informed about errors occured.
	After success with file opening, the Packet is initialized
	and the file is being parsed. The application can use the
	parsing result right after creating an instance of this
	class.
	**/
	public DictionaryParser()
	{
		while (FileName.size() > 0)
		{
			/* Try to open file */
			try
			{
				System.out.println("Opening File "+Path+(String)FileName.firstElement());
				FileDscr = new FileInputStream(Path+(String)FileName.firstElement());
				/* Parse the file */
				ParseDictionary();
				FileName.remove(0);
			}
			catch (FileNotFoundException e)
			{
	  			System.out.println(" File "+Path+FileName.firstElement()+" not found " );
	  			return;
			}
		}
	}


	/**
	This function is responsible for parsing the Dictionary 
	file. First the data for the parse is specified.
	**/
	public void ParseDictionary()
	{
		int TokenType;
		String PhoneType = new String();
		Reader r = new BufferedReader(new InputStreamReader(FileDscr));
		StreamTokenizer Tokenizer = new StreamTokenizer( r );
		int LineNumber = 0;

		/* Set Up the StreamTokenizer class */
		Tokenizer.parseNumbers();
		Tokenizer.eolIsSignificant(true);
		Tokenizer.commentChar('#');
//		Tokenizer.ordinaryChars('0','9');
//		Tokenizer.ordinaryChar('-');
		Tokenizer.ordinaryChar('+');
		Tokenizer.ordinaryChar(';');
		Tokenizer.ordinaryChar(':');
//		Tokenizer.ordinaryChar('.');
		Tokenizer.ordinaryChar('=');

		try
		{
			Tokenizer.nextToken();

			while ( Tokenizer.ttype != Tokenizer.TT_EOF )
			{
				/* Do not check empty tokens */
				if ( Tokenizer.sval != null)
				{
                                        if ( Tokenizer.sval.equals("ATTRIBUTE") )
                                        {
						Tokenizer.nextToken();							// next
                                                if ( Tokenizer.ttype == Tokenizer.TT_WORD )
						{
							if (! hash.containsKey("ATTRIBUTE"))
                                                        {
                                                                hash.put("ATTRIBUTE", new Hashtable());
                                                        }
							TmpCode = Tokenizer.sval;
                                                        Tokenizer.nextToken();						// next
                                                        TmpValeur = (int)  Tokenizer.nval;
							Tokenizer.nextToken();						// next
							TmpType = Tokenizer.sval;

							attributes = (Hashtable) hash.get("ATTRIBUTE");
							attributes.put(new Integer(TmpValeur), TmpType+" "+TmpCode);
                                                }
					}
					else if ( Tokenizer.sval.equals("VALUE") )
		  			{
		    				Tokenizer.nextToken();							// next
                                                if ( Tokenizer.ttype == Tokenizer.TT_WORD )
						{
							if (! hash.containsKey(Tokenizer.sval))
			                                {
                        			               	hash.put(Tokenizer.sval, new Hashtable());
                                                	}
							values = (Hashtable) hash.get(Tokenizer.sval);
							Tokenizer.nextToken();						// next
							TmpCode = Tokenizer.sval;
							Tokenizer.nextToken();						// next
							TmpValeur = (int)  Tokenizer.nval;

							if (TmpCode != null)
								values.put(new Integer(TmpValeur), TmpCode);
						}
					}
					else if ( Tokenizer.sval.equals("INCLUDE") )
                                        {
						Tokenizer.nextToken();
						FileName.add(Tokenizer.sval);
					}

					Tokenizer.nextToken();

					while ( Tokenizer.ttype != Tokenizer.TT_EOL )
					{
						Tokenizer.nextToken();
					}
					LineNumber++;
				}
	    			/* continue reading */
	    			Tokenizer.nextToken();
	  		}
	  	}
	  	catch (IOException e) { System.out.println ( e ); }
	}
	public static void setConstant( String dictionaire, Hashtable ht)
	{
		hash = ht;
                
		FileName.add(dictionaire.substring(dictionaire.lastIndexOf('/')+1));
		Path = dictionaire.substring(0, dictionaire.lastIndexOf('/')+1);

		DictionaryParser dictionary = new DictionaryParser();
	}

        /********************************************************************/
	public static final void main( String argv[] )
	{
		if (argv.length>0)
		{
			for (int i=0; i<argv.length; i++)
			{
				FileName.add(argv[i].substring(argv[i].lastIndexOf('/')+1));
				Path = argv[i].substring(0, argv[i].lastIndexOf('/')+1);
			}
		}
		else
		{
			FileName.add("dictionary");
			Path = "";
		}
		hash = new Hashtable();
		DictionaryParser dictionary = new DictionaryParser();
		System.out.println("Impressions : "+hash.toString());
	}
	/********************************************************************/       
}
