package September27;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class JavaConfig {
    static Scanner scan = new Scanner(System.in);

    public static void main(String[] args) {

        //Using configuration
        System.out.println("Using configuration\n");
        ApplicationContext context = new AnnotationConfigApplicationContext(StudentConfig.class);

        Student student = context.getBean(Student.class);
        student.setAge(28);
        student.setName("Chandan");

        System.out.println("Name : " + student.getName() + "\nAge : " + student.getAge());

        //using partial xml
        System.out.println("\nusing partial xml : @Autowired\n");

        ApplicationContext context_1 = new ClassPathXmlApplicationContext("applicationContext_1.xml");

        Teacher teacher = context_1.getBean("teacher", Teacher.class);

        teacher.student.setName("Chandan");
        teacher.student.setAge(22);

        System.out.println("Teacher name : " + teacher.name + " - id: " + teacher.id + " :: Student name : " + teacher.student.getName() + " - Age: " + teacher.student.getAge());

        Map<Teacher, Student> teacherStudentMap = new HashMap<>();
        int choose = 1;
        while (choose == 1) {
            Student student1 = new Student();
            System.out.println("\nenter the name of student,age");
            student1.setName(scan.next());
            student1.setAge(scan.nextInt());
            System.out.println("enter teacher name ,id");
            teacherStudentMap.put(new Teacher(scan.next(), scan.next()), student1);
            System.out.println("enter 1 to add or 0 to exit");
            choose = scan.nextInt();
        }
        for (Teacher key : teacherStudentMap.keySet()) {
            System.out.println(key.name + key.id + " : " + teacherStudentMap.get(key).getName() + teacherStudentMap.get(key).getAge());

        }


    }
}
