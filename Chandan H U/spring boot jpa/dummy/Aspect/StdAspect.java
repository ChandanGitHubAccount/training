package dummy.Aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.jetbrains.annotations.NotNull;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.stereotype.Component;

@Component
@Aspect
@EnableAspectJAutoProxy
public class StdAspect {

    @Before(value = "execution(public * addStud(..))")
    public void beforeAdvice(@NotNull JoinPoint joinPoint) {
        System.out.println("Before method:" + joinPoint.getSignature());
        System.out.println("Creating Student with  name - " + joinPoint.getKind());
    }
    @After(value = "execution(public * addStud(..))")
    public void afterAdvice(@NotNull JoinPoint jp) {
        System.out.println("Before method:" + jp.getSignature().getName());
        System.out.println("Creating Student with  name - " + jp.getKind());
    }
}
