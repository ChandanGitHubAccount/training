package September12;

import org.junit.jupiter.api.Test;

import static assignment3.Functions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static practices.FirstPositiveMissingElement.firstPositiveMissingNumberInArray;
import static practices.Solution.longestCommonPrefix;

class JUnitTest {
    @Test
    public void longestCommonPrefixTest(){
        String[] str = {" foo", " "};
        assertEquals(" ", longestCommonPrefix(str));
    }
    @Test
    public void firstPositiveMissingNumberInArrayTest() {
        int array[] = new int[]{-1,1, 2, 5, 15, 6, 7};
        assertEquals(3,firstPositiveMissingNumberInArray(array),"recheck program");
    }
    @Test
    public void findSubStringTest(){
        StringBuffer string = new StringBuffer("chandan");
        StringBuffer subString = new StringBuffer("cha");
        assertTrue(findSubString(string, subString));
    }
    @Test
    public void deleteCharAtTest(){
        StringBuffer string = new StringBuffer("chandan");
        int index = 6;
        assertEquals("chanda",deleteCharAt( string,index).toString());

    }
    @Test
    public void replaceSubStringTest(){
        StringBuffer string = new StringBuffer("chandan");
        StringBuffer subString = new StringBuffer("an");
        StringBuffer newString = new StringBuffer("u");
        assertEquals("chudan",replaceSubString( string,  subString,  newString).toString());
    }
    @Test
    public void reverseStringTest(){
        StringBuffer string = new StringBuffer("chandan");
        assertEquals("nadnahc",reverseString(string).toString());

    }
    public void mergedStringsTest(){
        StringBuffer string1 = new StringBuffer("ChAndan");
        StringBuffer string2 = new StringBuffer("SuMaNtH");
        assertEquals("CASMNH",mergedStrings(string1,string2));
    }


}
