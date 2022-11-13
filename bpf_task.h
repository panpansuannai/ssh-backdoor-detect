#pragma once
#include <string>

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

    void set_handler(handlerTy h);

    void poll_loop();

private:
    handlerTy handler;
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