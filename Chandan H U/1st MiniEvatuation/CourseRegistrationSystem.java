package September15MiniEvatuation;

import java.util.*;

class Admin {
    String adminId, passwordToLogin;

    Admin(String adminId, String passwordToLogin) {
        this.adminId = adminId;
        this.passwordToLogin = passwordToLogin;
    }
}

class Course {
    String courseCode, courseName, allocatedSection;
    int maximumNumberOfSeatsForCourse;

    public Course(String courseName, String courseCode, String allocatedSection, int maximumNumberOfSeatsForCourse) {
        this.courseName = courseName;
        this.courseCode = courseCode;
        this.allocatedSection = allocatedSection;
        this.maximumNumberOfSeatsForCourse = maximumNumberOfSeatsForCourse;
    }
}

class Student {
    String studentRollNumber, studentName, optedCourseCode, courseName, sectionAllocated;

    Student(String studentName, String studentRollNumber, String optedCourseCode, String courseName, String sectionAllocated) {
        this.studentName = studentName;
        this.studentRollNumber = studentRollNumber;
        this.optedCourseCode = optedCourseCode;
        this.courseName = courseName;
        this.sectionAllocated = sectionAllocated;

    }

}

class Management {
    private String managementPassword = "Robosoft@123";

    public void setManagementPassword(String managementPassword) {
        this.managementPassword = managementPassword;
    }

    public String getManagementPassword() {
        return managementPassword;
    }
}


public class CourseRegistrationSystem {
    //Management class object
    static Management management = new Management();
    //Admin class object
    static Map<String, Admin> adminList = new HashMap<>();
    //Course class object
    static Map<String, Course> course = new HashMap<>();
    //Student class object
    static Map<String, Student> students = new HashMap<>();
    //Admin function object
    static AdminFunctions adminFunctions = new AdminFunctions();
    //Student function object
    static StudentFunctions studentFunctions = new StudentFunctions();

    //Scanner class object
    static Scanner scan = new Scanner(System.in);

    public static void main(String[] args) {

        managementLogin();

        if (adminLogin())
            System.out.println("Invalid username and password.");

        studentLogin();
    }

    private static void managementLogin() {
        System.out.println("enter the login password");
        String managementPassword = scan.next();
        int numberOfAdmins = 1;
        System.out.println("enter\n1:update Admin details. \n2:change password.");
        int choice = scan.nextInt();
        switch (choice) {
            case 1 -> {
                if (managementPassword.equals(management.getManagementPassword())) {
                    System.out.println("management:set the number of employee who can have the admin rights.");
                    numberOfAdmins = scan.nextInt();
                }
                //Setting admins
                addAdminDetails(adminList, numberOfAdmins);
            }
            case 2 -> {
                //changing management password
                System.out.println("enter the new password that contain minimum 8 characters " +
                        "at least one upper case ,one lower case ,one special character and one number.");
                String changePassword = scan.next();
                management.setManagementPassword(changePassword);
            }
        }
    }

    private static void addAdminDetails(Map<String, Admin> adminList, int numberOfAdmins) {
        do {
            System.out.println("enter admin ID.");
            String adminId = scan.next();
            System.out.println("set the password for admin.");
            String password = scan.next();
            adminList.put(adminId, new Admin(adminId, password));
            numberOfAdmins--;
        } while (numberOfAdmins != 0);
    }

    private static boolean adminLogin() {
        System.out.println("enter the admin id.");
        String adminIdToLogin = scan.next();
        System.out.println("enter password to login.");
        String loginPassword = scan.next();
        if (!(adminList.containsKey(adminIdToLogin)
                && loginPassword.equals(adminList.get(adminIdToLogin).passwordToLogin)))
            return false;

        boolean check = true;
        while (check) {
            System.out.println("""
                    enter 1:Create a new course.\s
                    2:Delete a course.\s
                    3:Edit a course (except for course ID and name).\s
                    4:Display info for a course (by course ID).\s
                    5:Register a student (allows admin to add student w/o assigning to a course).\s
                    6:Exit.\s""");
            int chooseTheAction = scan.nextInt();
            switch (chooseTheAction) {
                case 1-> adminFunctions.addCourse(course);
                case 2-> adminFunctions.deleteCourse(course);
                case 3-> adminFunctions.editExistingCourse(course);
                case 4-> adminFunctions.displayInformationAboutCourse(course);
                case 5-> adminFunctions.registerTheStudent(course, students);
                case 6-> check = false;
            }
        }
        return true;
    }

    private static void studentLogin() {
        while (true) {
            System.out.println("""
                    select\s
                    1:View all courses.\s
                    2:View all courses that are NOT full.\s
                    3:Register in a course (student enters course name, section, student's full name).\s
                    4:Withdraw from a course (student enters their name, course name).\s
                    5:View all courses students registered.\s
                    6:Exit.\s""");
            int choose = scan.nextInt();
            switch (choose) {
                case 1-> studentFunctions.displayAllCourseAvailable(course);
                case 2-> studentFunctions.displayCourseThatAreNotFull(course);
                case 3-> studentFunctions.registerForCourse(course, students);
                case 4-> studentFunctions.withdrawFromCourse(course, students);
                case 5-> studentFunctions.viewStudentWhoAreRegistered(students);
                case 6-> {return;}
            }
        }

    }
}

class AdminFunctions {
    static Scanner scan = new Scanner(System.in);

    public void registerTheStudent(Map<String, Course> course, Map<String, Student> students) {
        System.out.println("enter the name of the student you want register and his register number.");
        String studentName = scan.next(), registerNumber = generateStudentRollNumber(students);
        students.put(registerNumber, new Student(studentName, registerNumber, "", "", ""));
        System.out.println("enter 1 if you want to assign course to the student else 0.");
        if (scan.nextInt() == 1) {
            System.out.println("enter course code u want to assign.");
            String courseCode = scan.next();
            while (true)
                if (course.get(courseCode).maximumNumberOfSeatsForCourse > 0) {
                    students.get(registerNumber).optedCourseCode = courseCode;
                    students.get(registerNumber).courseName = course.get(courseCode).courseName;
                    students.get(registerNumber).sectionAllocated = course.get(courseCode).allocatedSection;
                    break;
                } else System.out.println("seats for this course is full try for another course.");

        } else System.out.println("Course will be allocated by admin soon.");
    }

    private String generateStudentRollNumber(Map<String, Student> students) {
        System.out.println("enter the 10 digit unique roll number for student.");
        String studentRollNumber = scan.next();
        for (String keys : students.keySet())
            if (keys.equals(studentRollNumber)) {
                System.out.println("entered roll number is already exist so try another roll number.");
                generateStudentRollNumber(students);
            }

        return studentRollNumber;
    }

    public void displayInformationAboutCourse(Map<String, Course> course) {
        for (String keys : course.keySet())
            System.out.println("Course code : " + course.get(keys).courseCode + "\ncourse name : \n" +
                    course.get(keys).courseName);
    }

    public void editExistingCourse(Map<String, Course> course) {
        System.out.println("enter the course code you want to edit.");
        String courseCode = scan.next();
        if (course.containsKey(courseCode)) {
            System.out.println("enter the number to increase or decrease number of student for the course.");
            int numberOfStudent = scan.nextInt();
            increaseOrDecreaseNumberOfStudentPerCourse(course, numberOfStudent, courseCode);
        } else System.out.println("Invalid course code.");

    }

    private void increaseOrDecreaseNumberOfStudentPerCourse(Map<String, Course> course, int numberOfStudent, String courseCode) {
        System.out.println("select 1:Increase student seats. \n 2:Decrease student seats.");
        int choose = scan.nextInt();
        switch (choose) {
            case 1-> course.get(courseCode).maximumNumberOfSeatsForCourse += numberOfStudent;
            case 2-> {
                if (course.get(courseCode).maximumNumberOfSeatsForCourse < numberOfStudent)
                    System.out.println("Cannot decrease the seats.");
                else course.get(courseCode).maximumNumberOfSeatsForCourse -= numberOfStudent;
            }
        }
    }


    public void deleteCourse(Map<String, Course> course) {
        System.out.println("enter the course code that you want to delete.");
        String courseCode = scan.next();
        if (courseCode.equals(course.get(courseCode).courseCode))
            course.remove(courseCode);
        else System.out.println("Entered invalid course code.");
    }

    public void addCourse(Map<String, Course> course) {
        int choose;
        do {
            System.out.println("enter the course name,course code having 6 alpha numeric digits " +
                    "and maximum number of seats for this course.");
            String courseName = scan.next(), courseCode = scan.next(), allocatedSection = scan.next();
            int maximumNumberOfSeatsForCourse = scan.nextInt();
            course.put(courseCode, new Course(courseName, courseCode, allocatedSection, maximumNumberOfSeatsForCourse));
            System.out.println("enter 1 to add more course else 0.");
            choose = scan.nextInt();

        } while (choose == 1);
    }
}

class StudentFunctions {

    static Scanner scan = new Scanner(System.in);

    public void displayAllCourseAvailable(Map<String, Course> course) {
        for (String keys : course.keySet())
            System.out.println("Course code : " + course.get(keys).courseCode + "\ncourse name : " +
                    course.get(keys).courseName + "\nRemaining seats : " + course.get(keys).maximumNumberOfSeatsForCourse +
                    "\nSection allocated for this course : " + course.get(keys).allocatedSection);
    }

    public void displayCourseThatAreNotFull(Map<String, Course> course) {
        for (String keys : course.keySet())
            if (course.get(keys).maximumNumberOfSeatsForCourse > 0)
                System.out.println("Course code : " + course.get(keys).courseCode + "\ncourse name : " +
                        course.get(keys).courseName + "\nRemaining seats : " + course.get(keys).maximumNumberOfSeatsForCourse +
                        "\nSection allocated for this course : " + course.get(keys).allocatedSection);
    }

    public void registerForCourse(Map<String, Course> course, Map<String, Student> students) {
        displayCourseThatAreNotFull(course);
        System.out.println("enter the course code you want to join.");
        String courseCode = scan.next();
        System.out.println("enter the 10 digit roll number of student given during student registration.");
        String studentRollNumbers = scan.next();
        if (students.containsKey(studentRollNumbers) && course.containsKey(courseCode) && course.get(courseCode).maximumNumberOfSeatsForCourse > 0 ) {
            students.get(studentRollNumbers).courseName = course.get(courseCode).courseName;
            students.get(studentRollNumbers).optedCourseCode = courseCode;
            students.get(studentRollNumbers).sectionAllocated = course.get(courseCode).allocatedSection;
            course.get(courseCode).maximumNumberOfSeatsForCourse--;
        } else System.out.println("Invalid course code or roll number.please select valid course code or roll numbe.r");
    }

    public void withdrawFromCourse(Map<String, Course> course, Map<String, Student> students) {
        System.out.println("enter the student roll number and course code that you want to withdraw.");
        String studentRollNumber = scan.next(), courseCodeForWithdraw = scan.next();
        for (String keys : students.keySet())
            if (studentRollNumber.equals(keys) && students.get(keys).optedCourseCode.equals(courseCodeForWithdraw)) {
                students.remove(keys);
                course.get(courseCodeForWithdraw).maximumNumberOfSeatsForCourse++;
            }
            else System.out.println("entered roll number is invalid or student doest have course to withdraw.");

    }

    public void viewStudentWhoAreRegistered(Map<String, Student> students) {
        for (String keys : students.keySet())
            System.out.println("student name : " + students.get(keys).studentName + "\nstudent roll number : " + students.get(keys).studentRollNumber +
                    "\ncourse name : " + students.get(keys).courseName + "\ncourse code : " + students.get(keys).optedCourseCode +
                    "\nallocated section : " + students.get(keys).sectionAllocated);
    }
}
