//! `master_librarian_rust` binary entry point.

mod app;
mod cli;
mod config;
mod factory;
mod formatter;
mod models;
mod nvd;
mod pkgconfig;

use app::MasterLibrarianBuilder;
use factory::{ClapGetoptFactory, DefaultFormatterFactory, FormatterFactory, GetoptFactory};
use nvd::NvdClient;

fn main() {
    if let Err(error) = run() {
        eprintln!("fatal error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let getopt_factory = ClapGetoptFactory;
    let config = getopt_factory.build_config()?;

    let formatter_factory = DefaultFormatterFactory;
    let formatter = formatter_factory.build_formatter(&config)?;

    let app = MasterLibrarianBuilder::new()
        .config(config)
        .formatter(formatter)
        .nvd_client(NvdClient::new()?)
        .build()?;

    app.run()
}
