package dummy.Controller;

import dummy.Model.DummyStd;
import dummy.Service.StdService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StdController {
    @Autowired
    private StdService stdService;

    @PostMapping("/add")
    public DummyStd addStud(@RequestBody DummyStd dummyStd){
        return stdService.addStd(dummyStd);
    }
}
