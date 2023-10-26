// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::time::Duration;
use std::time::Instant;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;

use timer_heap::TimerHeap;
use timer_heap::TimerType;
use tquic::timer_queue::TimerQueue;

pub fn time_remaining_benchmark_with_same_timer(c: &mut Criterion) {
    let mut tq = TimerQueue::new();
    const RANGE: u64 = 10_000;
    for i in 0..RANGE {
        tq.add(0, Duration::from_secs(i), Instant::now());
    }
    c.bench_function("timer queue remaining", |b| {
        b.iter(|| tq.time_remaining(Instant::now()))
    });

    let mut th = TimerHeap::new();
    for i in 0..RANGE {
        th.upsert(0, Duration::from_secs(i), TimerType::Oneshot);
    }
    c.bench_function("timer heap remaining", |b| b.iter(|| th.time_remaining()));
}

pub fn time_remaining_benchmark_with_diff_timer(c: &mut Criterion) {
    let mut tq = TimerQueue::new();
    const RANGE: u64 = 10_000;
    for i in 0..RANGE {
        tq.add(i, Duration::from_secs(i), Instant::now());
    }
    c.bench_function("timer queue remaining", |b| {
        b.iter(|| tq.time_remaining(Instant::now()))
    });

    let mut th = TimerHeap::new();
    for i in 0..RANGE {
        th.upsert(i, Duration::from_secs(i), TimerType::Oneshot);
    }
    c.bench_function("timer heap remaining", |b| b.iter(|| th.time_remaining()));
}

pub fn time_expired_benchmark_with_same_timer(c: &mut Criterion) {
    let mut tq = TimerQueue::new();
    const RANGE: u64 = 10_000;
    for _ in 0..RANGE {
        tq.add(0, Duration::from_secs(0), Instant::now());
    }
    c.bench_function("timer queue expired", |b| {
        b.iter(|| tq.next_expire(Instant::now()))
    });

    let mut th = TimerHeap::new();
    for _ in 0..RANGE {
        th.upsert(0, Duration::from_secs(0), TimerType::Oneshot);
    }
    c.bench_function("timer heap expired", |b| b.iter(|| th.expired().next()));
}

pub fn time_expired_benchmark_with_diff_timer(c: &mut Criterion) {
    let mut tq = TimerQueue::new();
    const RANGE: u64 = 10_000;
    for i in 0..RANGE {
        tq.add(i, Duration::from_secs(0), Instant::now());
    }
    c.bench_function("timer queue expired", |b| {
        b.iter(|| tq.next_expire(Instant::now()))
    });

    let mut th = TimerHeap::new();
    for i in 0..RANGE {
        th.upsert(i, Duration::from_secs(0), TimerType::Oneshot);
    }
    c.bench_function("timer heap expired", |b| b.iter(|| th.expired().next()));
}

criterion_group!(
    benches,
    time_remaining_benchmark_with_same_timer,
    time_remaining_benchmark_with_diff_timer,
    time_expired_benchmark_with_same_timer,
    time_expired_benchmark_with_diff_timer,
);
criterion_main!(benches);
