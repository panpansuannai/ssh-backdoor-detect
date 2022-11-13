#pragma once
#include <string>
#include <thread>

#include <bcc/BPF.h>

template<class T>
struct BPFTask: public ebpf::BPF {
    using handlerTy = void(*)(void*, void*, int);
    BPFTask(std::string program, std::string event): 
        bpf_program(program), event_name(event), handler(nullptr) {
            init(bpf_program);
        }

    BPFTask(std::string program, std::string event, handlerTy hdl): 
        bpf_program(program), event_name(event), handler(hdl) {
            init(bpf_program);
    }
    ~BPFTask() {
        if(td!=nullptr) delete td;
    }

    void set_handler(handlerTy h);

    void poll_loop();

    void run_with_thread();
    void join();
    bool joinable();
private:
    handlerTy handler;
    std::thread* td;
    std::string bpf_program;
    std::string event_name;
};

template<class T>
void BPFTask<T>::set_handler(BPFTask<T>::handlerTy h) {
    handler = h;
}

template<class T>
void BPFTask<T>::poll_loop() {
    open_perf_buffer(event_name, handler, nullptr, nullptr, 128);

    while(true) {
        poll_perf_buffer(event_name);
    }
}

template<class T>
void BPFTask<T>::run_with_thread() {
    if(td!=nullptr) return;
    td = new std::thread([&](){
        this->poll_loop();
    });
}

template<class T>
void BPFTask<T>::join() {
    if(td==nullptr) return;
    td->join();
}

template<class T>
bool BPFTask<T>::joinable() {
    if(td==nullptr) return true;
    return td->joinable();
}