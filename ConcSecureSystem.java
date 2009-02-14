/**
 * CS361 Computer Security - Assignment 2
 * Authored by Khoi Dang and Chris Cunningham
 */

import java.util.*;
import java.io.*;

enum SecurityLevel {LOW, HIGH}

enum Command {WRITE, READ, SLEEP, CREATE, DESTROY, BADINSTRUCTION}
 
/**
 * Class implements Bell-LaPadula model.
 */
public class ConcSecureSystem 
{
	public static boolean verbose = false;
	
	/**
	 * Entry point for program execution.
	 * @param args
	 */
    public static void main (String args[])
    {
    	    	
    	if(args.length<1)
    		System.out.println("Give file name.");
    	else
    	{
    		if(args.length==2 && args[1].equalsIgnoreCase("v")) //give verbose output
    			verbose = true;
    		
    		
    		String tmp = "";
    		FileInputStream in = null;
    		try 
        	{
    			in = new FileInputStream(args[0]);
    			byte next = 0;
    			while((next = (byte)in.read()) != -1) 
    			{
    				tmp += (char)next;
    			}
    		} 
        	catch (FileNotFoundException e) 
        	{
    			System.err.println("File not found!");
    		}
        	catch (IOException e) 
        	{
    			e.printStackTrace();
    		}
        	finally
        	{
        		if(in != null)
        		{
        			try
        			{
        				in.close();
        			}
        			catch(IOException e)
        			{
        				e.printStackTrace();
        			}
        		}
        	}
    		
			ReferenceMonitor rm = new ReferenceMonitor();
			
			byte[] fileByteArray = (tmp+Character.toString('\000')).getBytes();
			
			SecureSubject hal = new SecureSubject("Hal", SecurityLevel.HIGH, rm, fileByteArray);
			rm.addSubjectLevel("hal", SecurityLevel.HIGH);
			
			String outputFile = args[0] + ".out";
			SecureSubject lyle = new SecureSubject("Lyle", SecurityLevel.LOW, rm, outputFile);
			rm.addSubjectLevel("lyle", SecurityLevel.LOW);
		
			hal.start();
			lyle.start();
    	}
    }
}

/**
 * RefernceMonitor controls all subject access to objects.
 */
class ReferenceMonitor 
{
	/* Each instance of ReferenceMonitor has its own object manager. 
	 * This design ensures that the objects cannot be accessed by going around the ReferenceMonitor */
    private ObjectManager om;
    
    //hashes containing security levels for objects and subjects
    private HashMap<String, SecurityLevel> objectLevels;
    private HashMap<String, SecurityLevel> subjectLevels;

    /**
     * Constructs instance of ReferenceMonitor.
     */
    public ReferenceMonitor()
    {
        om = new ObjectManager();
        objectLevels = new HashMap<String, SecurityLevel>();
        subjectLevels = new HashMap<String, SecurityLevel>();
    }

    /**
     * Executes instr only if the security levels of the subject and object in question
     * are such that the operation is permitted under the rules of Simple Security (reading) and 
     * the *-property (writing). 
     * @param name describes subject executing instruction
     * @param instr instruction subject wishes to execute
     * @return 0 if bad instruction given, read access denied, or write performed
     * @return value read if read access granted
     */
    public synchronized int executeInstruction(String name, Instruction instr)
    {
    	assert (instr.getCommand() != Command.SLEEP) : "Sleep instruction passed to reference monitor!";
        SecurityLevel subjectLevel = subjectLevels.get(name);
        SecurityLevel objectLevel = objectLevels.get(instr.getObjectName());
        int value = 0; //default for bad instruction
        
        switch(instr.getCommand())
        {
            case READ:
                //System.out.println(name + " reading " + instr.getObjectName() + ".");
                if(subjectLevel.compareTo(objectLevel) >= 0)
                {
                    value = om.getObjectValue(instr.getObjectName());
                    //System.out.println("Access Granted.  Value read: " + value);
                }
                else
                {
                	//System.out.println("Access Denied.");
                }
                break;

            case WRITE:
                //System.out.println(name + " writing " + instr.getValue() + " to " + instr.getObjectName() + ".");
                if(subjectLevel.compareTo(objectLevel) <= 0)
                {
                    om.setObjectValue(instr.getObjectName(), instr.getValue());
                    value = om.getObjectValue(instr.getObjectName());
                    //System.out.println("Access Granted.  Value written: " + value);
                }
                else
                {
                   //System.out.println("Access Denied.");
                }
                break;
                
            case CREATE:
            {
            	String objectName = instr.getObjectName();
            	
                //System.out.println(name + " creating " + objectName + " at level " + subjectLevel + ".");
                if(!om.contains(objectName))
                {
                    createNewObject(objectName, 0);
                    addObjectLevel(objectName, subjectLevel);
                    //System.out.println("Access Granted. " + objectName + " created.");
                }
                else
                {
                   //System.out.println(objectName + " already exists. No-op performed.");
                }
            
                break;
            }    
            case DESTROY:
            {
            	String objectName = instr.getObjectName();
            	
                //System.out.println(name + " destroying " + objectName + ".");
                if(om.contains(objectName))
                {
                	assert(objectLevel != null) : "Tried destroy. ObjectLevel was null";
            		assert(subjectLevel != null) : "Tried destroy. SubjectLevel was null";
                	if (subjectLevel.compareTo(objectLevel) <= 0) 
                	{
	                    om.destroyObject(objectName);
	                    removeObjectLevel(objectName);
	                    assert(objectLevels.get(instr.getObjectName()) == null) : "Object level not successfully removed";
	                    //System.out.println("Access Granted. " + objectName + " destroyed.");
                	}
                	else 
                	{
                		//System.out.println("Access Denied.");
                	}
                }
                else
                {   
                	//System.out.println(objectName + " does not exist. No-op performed.");
                }
                break;
            }
            default: 
            	//System.out.println(name + " gave bad instruction.");
                break;
        }

        if(om.contains("obj"))
        {	//System.out.println("Current State: obj = " + om.getObjectValue("obj"));
        	
        }
        else
        {
        	//System.out.println("Current State: obj doesn't exist.");
        }
        return value;
    }
    
    /**
     * Add subject name and security level to be maintained by ReferenceMonitor.
     * @param name subject name
     * @param s subject security level
     */
    public void addSubjectLevel(String name, SecurityLevel s)
    {
        subjectLevels.put(name, s);
    }
    
    /**
     * Get security level for subject.
     * @precondition name provide must be valid name of subject known to reference monitor
     * @param name subjects name
     * @return SecurityLevel of subject
     */
    public SecurityLevel getSubjectLevel(String name)
    {
        assert subjectLevels.get(name) != null : "No subject mapped to key \"" + name + "\".";
        return subjectLevels.get(name);
    }
    
    /**
     * Add object name and security level to be maintained by ReferenceMonitor.
     * @param name object name
     * @param s object security level
     */
    public void addObjectLevel(String name, SecurityLevel s)
    {
        objectLevels.put(name.toLowerCase(), s);
    }

    /**
     * Get security level for object.
     * @precondition name provided must be valid name of object known to reference monitor
     * @param name object's name
     * @return security level of object
     */
    public SecurityLevel getObjectLevel(String name)
    {
    	name = name.toLowerCase();
    	assert objectLevels.get(name) != null : "No object mapped to key \"" + name + "\".";
    	return objectLevels.get(name);
    }
    
    public void removeObjectLevel(String name)
    {
    	assert(objectLevels.get(name) != null) : "Tried removing object " + name + ". Didn't exist"; 
    	objectLevels.remove(name);
    }

    /**
     * Instructs underlying object manager to create a new object. 
     * Object names are not case sensitive and are set to all lower case.
     * @param name object's name
     * @param value object's value
     */
    public void createNewObject(String name, int value)
    {
        om.createNewObject(name, value);
    }

    /**
     * Class manages creation, modification and reading of objects.
     */
    private class ObjectManager
    {
    	//Map of objects managed
        private HashMap<String,SecureObject> objects;

        /**
         * Default constructor.
         */
        private ObjectManager()
        {
            objects = new HashMap<String,SecureObject>();
        }
        
        /**
         * Creates new object to be managed by manager.
         * @param name object's name
         * @param value object's value
         */
        private void createNewObject(String name, int value)
        {
            objects.put(name, new SecureObject(name, value));
        }
        
        private void destroyObject(String name)
        {
            objects.remove(name);
            assert(objects.get(name) == null) : "Object not successfully removed from OM.";
        }

        /**
         * Sets value of described object
         * @param name object's name
         * @param value to be set
         */
        private void setObjectValue(String name, int value)
        {
            SecureObject tmp = objects.get(name);
            assert (tmp != null) : "No object mapped to key \"" + name + "\".";

            tmp.setVal(value);
        }

        /**
         * Gets value of given object.
         * @param name object's name
         * @return value of object
         */
        private int getObjectValue(String name)
        {
            SecureObject tmp = objects.get(name);
            assert (tmp != null) : "No object mapped to key \"" + name + "\".";
            
            return tmp.getValue();
        }
        
        private boolean contains(String name) 
        {
        	return objects.containsKey(name);
        }

        /**
         * Class defines objects.
         */
        private class SecureObject
        {
            private String name;
            private int value;

            /**
             * Constructor
             * @param name object's name
             * @param value object's value
             */
            private SecureObject(String name, int value)
            {
                this.name = name;
                this.value = value;
            }

            /**
             * @return object name
             */
			private String getName()
            {
                return name;
            }

			/**
			 * @return object value
			 */
            private int getValue()
            {
                return value;
            }

            /**
             * Set this object's value
             * @param value new value to be set
             */
            private void setVal(int value)
            {
                this.value = value;
            }
        }//SecureObject
    }//ObjectManager
}//ReferenceMonitor

/*
 * Defines subjects.
 */
class SecureSubject extends Thread
{
    private String name;
    private SecurityLevel securityLevel;
    private ReferenceMonitor referenceMonitor;
    private ArrayList<Instruction> instructions;
    private int bitCount;
    private long startTime, stopTime;
    private boolean[] bits;
    public static final double NANOS_PER_SEC = 1000000000.0;
    private static String outputFile = "output.txt";

    
    /**
     * Lyles Constructor.
     * @param name subject name
     * @param s subject security level
     * @param r reference monitor controlling subject access to objects
     */
    public SecureSubject(String name, SecurityLevel s, ReferenceMonitor r, String outFile) 
    {
        this.name = name;
        securityLevel = s;
        referenceMonitor = r;
        instructions = new ArrayList<Instruction>();
        bits = null;
        bitCount = 0;
        outputFile = outFile;
    }
    
    /**
     * Hals constructor.
     * @param name subject name
     * @param s subject security level
     * @param r reference monitor controlling subject access to objects
     * @param arr contains chars in file represented as bytes
     */
    public SecureSubject(String name, SecurityLevel s, ReferenceMonitor r, byte[] arr) 
    {
        this.name = name;
        securityLevel = s;
        referenceMonitor = r;
        instructions = new ArrayList<Instruction>();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(arr);
        bitCount = 0;
        
        bits = new boolean[8*arr.length];	//bits holds the bits from byte array
        int temp = 0;
        int count = 0;
        
        while((temp = inputStream.read()) != -1)//masking and shifting to get bits
        {
        	for(int i = 0; i < 8; i++, count++) 
        	{
        		bits[count] = ((temp & 128) == 128 ? true : false);
        		temp <<= 1;
        	}
        }
    }
    
    /**
     * @return subject's name
     */
    public String getSubjectName() 
    {
		return name;
	}

    /**
     * @return subject's security level
     */
	public SecurityLevel getSecurityLevel() 
	{
		return securityLevel;
	}

	/**
	 * @return subject's reference monitor
	 */
	public ReferenceMonitor getReferenceMonitor() 
	{
		return referenceMonitor;
	}

	/**
	 * Invoked when subject thread's start() method executed.
	 * Attempts to execute instructions in file, passing them to the reference monitor.
	 */
	public synchronized void run()
    {
		System.nanoTime();

        if(name.equalsIgnoreCase("hal"))
        	halAction();
        else
        	lyleAction();
    }
	
	public void halAction()
	{
		startTime = System.nanoTime();
		for(int i = 0; i<bits.length; i++) 
		{
			String verbosePrint = "";
			if(Token.hasToken("hal"))
			{
				if(!bits[i])
				{
					verbosePrint += "Hal - creates object obj (signals 0)";
					referenceMonitor.executeInstruction("hal", new Instruction(Command.CREATE, "obj", 0));
				}
				else					
					verbosePrint += "Hal - does nothing (signals 1)";
				
				if(ConcSecureSystem.verbose)
					System.out.println(verbosePrint);
				
				Token.passToken();
			}
		}

		stopTime = System.nanoTime();
		double numSeconds = (stopTime - startTime)/NANOS_PER_SEC;
		
		System.out.println("Moved " + bits.length + " bits in " + numSeconds + " seconds.");
		System.out.println("Bandwidth = " + bits.length/numSeconds + " bits/second");
	}
	
	public void lyleAction()
	{
		int myByte = 0;
		ArrayList<Character> chars = new ArrayList<Character>();
		while(true)
		{
			String verbosePrint = "";
			if(Token.hasToken("lyle"))
			{
				//used covert channel described in spec
				referenceMonitor.executeInstruction("lyle", new Instruction(Command.CREATE, "obj", 0));
				verbosePrint += "Lyle - created object obj\n";
				referenceMonitor.executeInstruction("lyle", new Instruction(Command.WRITE, "obj", 1));
				verbosePrint += "Lyle - wrote '1' to obj\n";
				int value = referenceMonitor.executeInstruction("lyle", new Instruction(Command.READ, "obj", 0));
				if(value == 1)
					verbosePrint += "Lyle - read '1' from obj obj (received signal 1)\n";
				else
					verbosePrint += "Lyle - read '0' from obj obj (received signal 0)\n";
				referenceMonitor.executeInstruction("lyle", new Instruction(Command.DESTROY, "obj", 0));
				verbosePrint += "Lyle - destroyed obj\n";
				
				if(ConcSecureSystem.verbose)
					System.out.println(verbosePrint);
				
				myByte <<= 1;
				myByte |= value;
				bitCount++;
				
				if(bitCount == 8)
				{
					chars.add((char)myByte);
					myByte = 0;
					bitCount = 0;

					if (chars.get(chars.size()-1) == 0) 	//checks if last thing was null char
						break;
				}
				Token.passToken();
			}
		}
		
		
		//printing out to file		
		FileOutputStream out = null;
		try
		{
			out = new FileOutputStream(outputFile);
			for(int i = 0; i<chars.size()-1; i++)
				out.write(chars.get(i));
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		finally
		{
			if(out != null)
				try {
					out.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
		}		
	}
}

/**
 * Constructor class to parse in the instructions from file.
 */
class Instruction 
{	
//	public static final String WRITE = "write";
//	public static final String READ = "read";
//	public static final String SLEEP = "sleep";
//	public static final String LOBJ = "lobj";
//	public static final String HOBJ = "hobj";
	
	private Command command;
    private	String objName;
    private	int value;
	
    /**
     * Constructor for Instruction Objects.
     * 
     * @param command command in the instruction (sleep, read, write, or bad instruction)
     * @param objName name of the object (hobj or lobj)
     * @param value value for write command
     */
	Instruction(Command command, String objName, int value)
    {
		this.command = command;
		this.objName = objName.toLowerCase();
		this.value = value;
	}
	
	/**
	 * @return instruction's command: sleep, read, write, or bad instruction.
	 */
	public Command getCommand() 
    {
		return command;
	}
	
	/**
	 * @return instruction's object name: hobj or lobj.
	 */
	public String getObjectName() 
    {
		return objName;
	}
	
	/**
	 * @return instruction's value for write command.
	 */
	public int getValue() 
    {
		return value;
	}    
}
