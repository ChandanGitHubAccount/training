package practices;

public class DuplicateWords {
    public  static void main(String args[]){
        String string = new String("i am in in i robo robo robosoft");
            int value = 0,count=0,NumOfWord=0;
            String word = new String("");
            for(int index=0 ; index< string.length() ; index++)
                if(string.charAt(index) == 32)
                    value++;

            String words[] = new String[value+1];

            for(int index=0 ; index< string.length() ; index++)
                if(string.charAt(index) != 32 || index == string.length())
                    word += string.charAt(index);
                else{
                    words[count] = word;
                    word = "";
                    count++;
                }
            for(int index=0 ; index< words.length ; index++)
                for(int indexs=index+1 ; indexs<words.length && indexs!=index ; indexs++)
                    if(words[index].equals(words[indexs]))
                        System.out.print(words[indexs]+" ");
    }
}
