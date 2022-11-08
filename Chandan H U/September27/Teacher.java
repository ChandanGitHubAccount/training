package September27;

import org.springframework.beans.factory.annotation.Autowired;

public class Teacher {
    String name , id;
    @Autowired
    Student student;

   //Map<String,Student> stringStringMap = new HashMap<>();

    public Teacher(String name , String id ) {
        this.id = id;
        this.name = name;
    }

}
