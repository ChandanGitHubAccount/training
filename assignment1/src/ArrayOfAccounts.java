
import java.util.*;

public class ArrayOfAccounts {
    public static void main(String args[]){
        Scanner sacn = new Scanner(System.in);
        System.out.println("enter the number of accounts needs to be opened");
        int option,count = sacn.nextInt();
        AccountInfomation account[] = new AccountInfomation[count];
        for(int index=0 ; index<count ; index++) {
            account[index] = new AccountInfomation();
            System.out.println("deposit the amount more than 100 to open account");
            account[index].setBalance(sacn.nextDouble());
            System.out.println("set account id");
            account[index].setid(sacn.nextInt());
            System.out.println("set the annual interst of rate");
            account[index].setannualInterestRate(sacn.nextDouble());
        }
        do {
            System.out.println("enter the account id you need to inspect");
            int accountId = sacn.nextInt();

            System.out.println("choose action to be performed on account\n1:account created date\n2:withdraw\n3:deposit\n4:monthly intrest\n5:remaining balance");
            int choice = sacn.nextInt();

            switch (choice) {
                case 1:
                    System.out.println("account created date:" + account[accountId].getdateCreated());
                    break;
                case 2:
                    System.out.println("enter the amount to be withdraw from account");
                    account[accountId].withdraw(sacn.nextDouble());
                    System.out.println("remaining balance:"+account[accountId].getBalance());
                    break;
                case 3:
                    System.out.println("enter the amount to be deposited to account");
                    account[accountId].deposit(sacn.nextDouble());
                    System.out.println("remaining balance:"+account[accountId].getBalance());
                    break;
                case 4:
                    System.out.println(account[accountId].getMonthlyInterest());
                    break;
                case 5:
                    System.out.println(account[accountId].getBalance());
                    break;
                default:
                    System.out.println("u have entered wrong choice");
            }
            System.out.println("enter 1 to perform again or 0 to exit");
            option = sacn.nextInt();
        } while (option == 1);
    }
}

