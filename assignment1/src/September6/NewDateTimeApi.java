package September6;

import java.time.*;
import java.util.Scanner;

public class NewDateTimeApi {
    static Scanner scan = new Scanner(System.in);
    public static void main(String[] args) {
        LocalTime currentTime = LocalTime.now();
        System.out.println("current time:"+currentTime);

        LocalDate currentDate = LocalDate.now();
        System.out.println("current date:"+currentDate);

        LocalDateTime dateAndTime = LocalDateTime.now();
        System.out.println("current date and time:"+dateAndTime);

        LocalDate dateEntered = LocalDate.of(2000, Month.MAY, 2);
        System.out.println("entered date:"+dateEntered);

        LocalTime timeEntered = LocalTime.of(13,45,12,5555);
        System.out.println("entered time:"+timeEntered);

        LocalDateTime dateTimeEntered = LocalDateTime.of(2000,Month.MAY,2,13,45,12,5555);
        System.out.println("entered date and time:"+dateTimeEntered);

        Duration differenceInTime = Duration.between(currentTime,timeEntered);
        System.out.println("gap in time:"+differenceInTime);

        Period differenceInDate = Period.between(currentDate,dateEntered);
        System.out.println("gap in date:"+differenceInDate);

        LocalTime addFiveHours = currentTime.plus(Duration.ofHours(5));
        System.out.println("after adding 5 hours to current time:"+addFiveHours);

        LocalDate addFiveYears = currentDate.plus(Period.ofYears(5));
        System.out.println("after adding 5 years to current date:"+addFiveYears);

        LocalDate birthDay = LocalDate.of(2000,Month.MAY,2);
        System.out.println("age of person:"+Period.between(birthDay, LocalDate.now()).getYears()+" years");

        System.out.println("enter the year to check its leap or not");
        int year = scan.nextInt();
        if(LocalDate.now().withYear(year).isLeapYear())
            System.out.println("year is leap");
        else
            System.out.println("year is not leap");

        System.out.println("enter the year to check its leap or not using Year class");
        int years = scan.nextInt();
        if (Year.of(years).isLeap())
            System.out.println(year + " is leap year");
        else
            System.out.println(year + " not leap year");

        if(birthDay.getMonth() == currentDate.getMonth() && birthDay.getDayOfMonth() == currentDate.getDayOfMonth())
            System.out.println("today is your birthday");
        else
            System.out.println("today is not your birthday");

    }
}
