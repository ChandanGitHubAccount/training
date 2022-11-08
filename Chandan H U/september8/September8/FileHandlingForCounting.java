package September8;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class FileHandlingForCounting {
    static FileReader  file;
    public static void main(String[] args) throws IOException {
        file = new FileReader("D:\\FileHandling\\file3.txt");
        System.out.println("number of character in the file:"+getCharCount());
        System.out.println("Number of words in the file:"+getWordCount());
    }
    private static int getCharCount() throws IOException{
        file = new FileReader("D:\\FileHandling\\file3.txt");
        int countChar = 0;
        while (file.read() != -1){
            countChar ++;
        }

        return countChar;
    }
    private static int getWordCount() throws IOException{
        FileReader  file = new FileReader("D:\\FileHandling\\file3.txt");
        int wordCount = 0,lineCount=0;
        BufferedReader covertedFile = new BufferedReader(file);
        String line;
        while ((line=covertedFile.readLine()) != null){
            lineCount++;
            String words[] = line.split(" ");
            wordCount += words.length;
        }
        System.out.println("Number of line in the file:"+lineCount);
        file.close();
        return wordCount;
    }
}
