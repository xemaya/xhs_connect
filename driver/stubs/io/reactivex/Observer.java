package io.reactivex;

public interface Observer<T> {
    void onSubscribe(h4d.c d);

    void onNext(T t);

    void onError(Throwable e);

    void onComplete();
}
