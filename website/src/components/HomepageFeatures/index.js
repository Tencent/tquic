import React from 'react';
import clsx from 'clsx';
import styles from './styles.module.css';
import Translate from '@docusaurus/Translate';

/* To be updated */
const FeatureList = [
  {
    title: <Translate id="feature.High performance.title">High Performance</Translate>,
    Svg: require('@site/static/img/high-performance.svg').default,
    description: (
      <>
        <Translate id="feature.High performance.description">TQUIC is designed for high performance and low latency.</Translate>
      </>
    ),
  },
  {
    title: <Translate id="feature.High throughput.title">High Throughput</Translate>,
    Svg: require('@site/static/img/high-throughput.svg').default,
    description: (
      <>
	<Translate id="feature.High throughput.description">TQUIC supports various congtestion control algorithms (CUBIC, BBR, COPA), 
	and Multipath QUIC for utilizing multiple paths within a single connection.</Translate>
      </>
    ),
  },
  {
    title: <Translate id="feature.High quality.title">High Quality</Translate>,
    Svg: require('@site/static/img/high-quality.svg').default,
    description: (
      <>
	<Translate id="feature.High quality.description">
	TQUIC employs extensive testing techniques, including unit testing, fuzz testing, 
	integration testing, benchmarking, interoperability testing, and protocol conformance testing.
        </Translate>
      </>
    ),
  },
  {
    title: <Translate id="feature.Easy to Use.title">Easy to Use</Translate>,
    Svg: require('@site/static/img/easy-to-use.svg').default,
    description: (
      <>
	<Translate id="feature.Easy to Use.description">
	TQUIC is easy to use, with flexible configuration and detailed observability.
	It offers APIs for Rust/C/C++.
        </Translate>
      </>
    ),
  },
  {
    title: <Translate id="feature.Powered by Rust.title">Powered by Rust</Translate>,
    Svg: require('@site/static/img/power-by-rust.svg').default,
    description: (
      <>
	<Translate id="feature.Powered by Rust.description">
	TQUIC is written in a memory-safe language, making it immune to Buffer Overflow 
	vulnerability and other memory-related bugs.
        </Translate>
      </>
    ),
  },
  {
    title: <Translate id="feature.Rich features.title">Rich Features</Translate>,
    Svg: require('@site/static/img/rich-features.svg').default,
    description: (
      <>
	<Translate id="feature.Rich features.description">
        TQUIC supports all major features conforming to QUIC, HTTP/3 RFCs.
        </Translate>
      </>
    ),
  },
];

function Feature({Svg, title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
