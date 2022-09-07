package assignment3;

import java.util.StringTokenizer;

public class Functions {
    static boolean findSubString(StringBuffer string, StringBuffer subString) {
        int count = 0;
        for (int index = 0; index < string.length() && count< subString.length(); index++) {
            if (string.charAt(index) == subString.charAt(count))
                count++;
            else
                count = 0;

            if (count == subString.length())

                return true;
        }
        return false;
    }
    static StringBuffer deleteCharAt(StringBuffer string,int index){
        return (string.replace(index,index+1,""));
    }
    static StringBuffer replaceSubString(StringBuffer string , StringBuffer subString ,StringBuffer newString){
        boolean result = findSubString(string,subString);
        if(result == false){
        return new StringBuffer("substiring not found , cannot perform the operation");}
        else{
            int startIndex = string.indexOf(String.valueOf(subString));
            int endIndex = subString.length()+startIndex;
            return string.replace(startIndex,endIndex, String.valueOf(newString));
        }
    }
    static StringBuffer reverseString(StringBuffer string){
        for(int index=0 ; index< string.length()/2 ; index++){
            int starting = index;
            int ending = (string.length()-1-index);
            char start = string.charAt(starting);
            char end = string.charAt(ending);
            string.setCharAt(starting,end);
            string.setCharAt(ending,start);
        }
        return string;
    }
    static void duplicateWordsInString(StringBuffer string){
        int value = 0,count=0,NumOfWord=0;
        StringBuffer word = new StringBuffer("");
        for(int index=0 ; index< string.length() ; index++)
            if(string.charAt(index) == 32)
                value++;

        StringBuffer words[] = new StringBuffer[value+1];

        for(int index=0 ; index< string.length() ; index++)
            if(string.charAt(index) != 32 || index == string.length())
                word.append(string.charAt(index));
            else{
                words[count] = word;
                word = new StringBuffer();
                count++;
            }
        for(int index=0 ; index< words.length-1 ; index++)
            for(int indexs=0 ; indexs<words.length-1 && indexs!=index ; indexs++)
                if(words[index].toString().equals(words[indexs].toString())) {
                    System.out.print(words[index]+" ");
                }
    }
    static void mergedStrings(StringBuffer string1 , StringBuffer string2){
        StringBuffer mergedString1 = new StringBuffer();
        for(int index=0 ; index< string1.length() ; index++)
            if(string1.charAt(index) >= 'A' && string1.charAt(index) <= 'Z' )
                mergedString1.append(string1.charAt(index));
        for(int index=0 ; index< string2.length() ; index++)
            if( string2.charAt(index) >= 'A' && string2.charAt(index) <= 'Z')
                mergedString1.append(string2.charAt(index));
        System.out.println(mergedString1);
    }
}
