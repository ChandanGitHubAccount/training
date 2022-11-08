package example.InsuranceDatabase.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Participated {
    String driver_id,regNo;
    int report_no , damage_amt;
}
