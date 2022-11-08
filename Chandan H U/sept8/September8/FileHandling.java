package September8;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class FileHandling {
    public static void main(String[] args) throws IOException {
        FileReader firstFile = null;
        FileReader secondFile = null;
        FileWriter outputFile = null;

        try {
            firstFile = new FileReader("D:\\FileHandling\\file1.txt");
            secondFile = new FileReader("D:\\FileHandling\\file2.txt");
            outputFile = new FileWriter("D:\\FileHandling\\file3.txt");
            int c,d;
            while (( c=firstFile.read()) != -1 )
                outputFile.write(c);
                while ((d =secondFile.read()) != -1)
                    outputFile.write(d);
        } finally {
            if (firstFile != null)
                firstFile.close();
            if (secondFile != null)
                secondFile.close();
            if(outputFile != null)
                outputFile.close();
        }
    }
}
