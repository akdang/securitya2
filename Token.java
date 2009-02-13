/**
 * CS361 Computer Security - Assignment 2
 * Authored by Khoi Dang and Chris Cunningham
 */

import java.util.*;
import java.io.*;

public class Token 
{
   
    // the token initially has value "hal"
    private static String current = "hal";

    public static synchronized void passToken () {
    // the value toggles back and forth between "hal" and "lyle"
    if ( current.equals("hal") ) {
        current = "lyle";
    } else { 
	current = "hal"; 
    }
    try {
        Token.class.notify();
	// This should work but some students had problems.
	//Class.forName("HasToken").notify();
    } catch (Exception e) {}
    } // passToken

    public static synchronized boolean hasToken (String user) {
    try {
        if ( ! current.equals(user) )
        {
                Token.class.wait();
        		
        }
    }
    catch (InterruptedException e) { }
    finally { return true; }
    } // hasToken

}