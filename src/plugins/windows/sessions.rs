//! windows.sessions.Sessions (python `plugins/windows/sessions.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin, ReqKind, Requirement, TimeKind, TimelineEvent};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::WinExt;

pub struct Sessions;

/// The row python collects for one process (before grouping).
fn proc_row(proc: &Obj) -> Result<Vec<Value>> {
    let session_id = proc.get_session_id()?;
    let mut session_type = Value::NotAvailable;
    let (mut user_domain, mut user_name) = (String::new(), String::new());
    // python: environment_variables() calls add_process_layer() outside its try block
    proc.add_process_layer()?;
    for (var, val) in proc.environment_variables() {
        let l = var.to_lowercase();
        if l == "username" {
            user_name = val.clone();
        } else if l == "userdomain" {
            user_domain = val.clone();
        }
        if l == "sessionname" {
            session_type = Value::Str(val);
        }
    }
    let full_user = format!("{user_domain}/{user_name}");
    let full_user = if full_user == "/" { Value::NotAvailable } else { Value::Str(full_user) };
    Ok(vec![
        session_id,
        session_type,
        Value::Int(proc.m("UniqueProcessId")?.int()?),
        Value::Str(array_to_string(&proc.m("ImageFileName")?, None)?),
        full_user,
        proc.get_create_time()?,
    ])
}

/// python `_generator`: rows grouped by session id in first-seen order. Absent session ids
/// are distinct objects in python (identity-hashed dict keys), so each forms its own group.
fn rows(ctx: &Context, cfg: &Config) -> Result<Vec<Vec<Value>>> {
    let k = ctx.windows_kernel()?;
    let pids = cfg.get_ints("pid");
    let filter = super::pslist::pid_filter(&pids);
    let procs = super::pslist::list_processes(k, &filter);
    let per_proc = crate::util::par::par_map(procs.len(), |i| match &procs[i] {
        Ok(p) => Some(proc_row(p)),
        Err(_) => None,
    });
    let mut groups: Vec<(Option<i128>, Vec<Vec<Value>>)> = Vec::new();
    for (p, r) in procs.into_iter().zip(per_proc) {
        p?;
        let row = r.expect("row computed for every listed process")?;
        let key = match row[0] {
            Value::Int(i) => Some(i),
            _ => None,
        };
        match key.and_then(|k| groups.iter_mut().find(|(g, _)| *g == Some(k))) {
            Some((_, rows)) => rows.push(row),
            None => groups.push((key, vec![row])),
        }
    }
    Ok(groups.into_iter().flat_map(|(_, r)| r).collect())
}

impl Plugin for Sessions {
    fn name(&self) -> &'static str {
        "windows.sessions.Sessions"
    }
    fn description(&self) -> &'static str {
        "lists Processes with Session information extracted from Environmental Variables"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new("pid", "Process IDs to include (all other processes are excluded)", ReqKind::ListInt).optional()]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Session ID", ColType::Int),
            Column::new("Session Type", ColType::Str),
            Column::new("Process ID", ColType::Int),
            Column::new("Process", ColType::Str),
            Column::new("User Name", ColType::Str),
            Column::new("Create Time", ColType::DateTime),
        ])?;
        for r in rows(ctx, cfg)? {
            out.row(0, r)?;
        }
        Ok(())
    }
    fn timeline(&self, ctx: &Context, cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        Some(rows(ctx, cfg).map(|rows| {
            rows.into_iter()
                .filter_map(|r| {
                    let Value::Str(user) = &r[4] else { return None };
                    let pid = match &r[2] {
                        Value::Int(i) => i.to_string(),
                        _ => String::new(),
                    };
                    let name = match &r[3] {
                        Value::Str(s) => s.as_str(),
                        _ => "",
                    };
                    Some(TimelineEvent {
                        description: format!("Process: {pid} {name} started by user {user}"),
                        kind: TimeKind::Created,
                        time: r[5].clone(),
                    })
                })
                .collect()
        }))
    }
}
