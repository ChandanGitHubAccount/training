package dummy.Service;

import dummy.Model.DummyStd;
import dummy.Repository.StdRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class StdService {

    @Autowired
    private StdRepository stdRepository;

    public DummyStd addStd(DummyStd dummyStd){
        return stdRepository.save(dummyStd);
    }
}
