package example.InsuranceDatabase.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Accident {
    private int report_no;
    private String Location;
    private Date  acc_date ;
}
