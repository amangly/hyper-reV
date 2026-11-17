use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const LOADER_PATH: &str = r"\EFI\hyper-reV\uefi-boot-standalone.efi";
pub const WINDOWS_PATH: &str = r"\EFI\Microsoft\Boot\bootmgfw.efi";
pub const DESCRIPTION: &str = "hyper-reV";
pub const SAFE_DESCRIPTION: &str = "Safe Windows";
const END_NODE: &[u8] = &[0x7f, 0xff, 4, 0];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Variable {
    pub attributes: u32,
    pub data: Vec<u8>,
}

pub trait Firmware {
    fn get(&self, name: &str) -> Result<Option<Variable>>;
    fn put(&mut self, name: &str, value: Option<&Variable>) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct LoadOption {
    pub attributes: u32,
    pub description: String,
    pub nodes: Vec<Vec<u8>>,
    pub optional_data: Vec<u8>,
}

impl LoadOption {
    pub fn parse(data: &[u8]) -> Result<Self> {
        ensure!(data.len() >= 8, "Truncated EFI_LOAD_OPTION");
        let attributes = u32::from_le_bytes(data[0..4].try_into()?);
        let path_length = u16::from_le_bytes(data[4..6].try_into()?) as usize;
        let mut position = 6;
        while position + 2 <= data.len() && data[position..position + 2] != [0, 0] {
            position += 2;
        }
        ensure!(position + 2 <= data.len(), "Unterminated boot description");
        let description = decode_utf16(&data[6..position])?;
        let start = position + 2;
        let end = start
            .checked_add(path_length)
            .context("Device path length overflow")?;
        ensure!(end <= data.len(), "Truncated device path");
        position = start;
        let mut nodes = Vec::new();
        while position < end {
            ensure!(end - position >= 4, "Truncated device path header");
            let size = u16::from_le_bytes(data[position + 2..position + 4].try_into()?) as usize;
            ensure!(
                size >= 4 && position + size <= end,
                "Invalid device path node length"
            );
            nodes.push(data[position..position + size].to_vec());
            position += size;
        }
        ensure!(
            nodes.last().is_some_and(|node| node == END_NODE),
            "Missing device path terminator"
        );
        ensure!(
            nodes[..nodes.len() - 1].iter().all(|node| node[0] != 0x7f),
            "Multiple device path instances are unsupported"
        );
        Ok(Self {
            attributes,
            description,
            nodes,
            optional_data: data[end..].to_vec(),
        })
    }

    pub fn file_path(&self) -> Result<String> {
        let paths: Vec<_> = self
            .nodes
            .iter()
            .filter(|node| node[0..2] == [4, 4])
            .collect();
        ensure!(paths.len() == 1, "Expected one file path node");
        let text = decode_utf16(&paths[0][4..])?;
        ensure!(text.ends_with('\0'), "File path is unterminated");
        ensure!(
            !text[..text.len() - 1].contains('\0'),
            "File path contains embedded NUL"
        );
        Ok(text.trim_end_matches('\0').to_owned())
    }

    pub fn partition_id(&self) -> Result<Uuid> {
        let drives: Vec<_> = self
            .nodes
            .iter()
            .filter(|node| node[0..2] == [4, 1])
            .collect();
        ensure!(
            drives.len() == 1 && drives[0].len() == 42,
            "Expected one GPT hard-drive node"
        );
        let drive = drives[0];
        ensure!(
            drive[40..42] == [2, 2],
            "Expected a GPT/GUID partition signature"
        );
        Ok(Uuid::from_bytes_le(drive[24..40].try_into()?))
    }
}

fn decode_utf16(data: &[u8]) -> Result<String> {
    ensure!(data.len().is_multiple_of(2), "Odd UTF-16 byte count");
    let words: Vec<_> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| u16::from_le_bytes([word[0], word[1]]))
        .collect();
    String::from_utf16(&words).context("Invalid UTF-16 in boot option")
}

fn utf16_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

pub fn indices(variable: &Variable) -> Result<Vec<u16>> {
    ensure!(
        !variable.data.is_empty() && variable.data.len().is_multiple_of(2),
        "Malformed boot-option list"
    );
    let values: Vec<_> = variable
        .data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|value| u16::from_le_bytes([value[0], value[1]]))
        .collect();
    let unique: BTreeSet<_> = values.iter().copied().collect();
    ensure!(
        values.len() == unique.len(),
        "Boot order contains duplicate entries"
    );
    Ok(values)
}

pub fn index(variable: &Variable) -> Result<u16> {
    ensure!(variable.data.len() == 2, "Malformed single boot index");
    Ok(u16::from_le_bytes(variable.data[..2].try_into()?))
}

pub fn boot_number(name: &str) -> Result<u16> {
    ensure!(
        name.len() == 8
            && name.starts_with("Boot")
            && name[4..].bytes().all(|c| c.is_ascii_hexdigit()),
        "Expected Boot#### reference"
    );
    u16::from_str_radix(&name[4..], 16).context("Invalid boot option index")
}

pub fn make_option(reference: &Variable, esp: Uuid) -> Result<Variable> {
    option_for(reference, esp, LOADER_PATH, DESCRIPTION, false)
}

pub fn make_safe_option(reference: &Variable, esp: Uuid) -> Result<Variable> {
    option_for(reference, esp, WINDOWS_PATH, SAFE_DESCRIPTION, true)
}

fn option_for(
    reference: &Variable,
    esp: Uuid,
    target: &str,
    description: &str,
    preserve_optional: bool,
) -> Result<Variable> {
    let option = LoadOption::parse(&reference.data)?;
    ensure!(
        option.attributes & 1 == 1,
        "The Windows reference option is inactive"
    );
    ensure!(
        option.partition_id()? == esp,
        "Windows boot option belongs to another ESP"
    );
    ensure!(
        option.file_path()?.eq_ignore_ascii_case(WINDOWS_PATH),
        "Reference does not target the stock Windows boot manager"
    );
    let files: Vec<_> = option
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node[0..2] == [4, 4])
        .collect();
    ensure!(
        files.len() == 1 && files[0].0 == option.nodes.len() - 2,
        "Expected a final file path after the hardware path"
    );
    let mut path = Vec::new();
    for node in &option.nodes[..files[0].0] {
        path.extend(node);
    }
    let file_text = utf16_bytes(target);
    path.extend([4, 4]);
    path.extend(u16::try_from(file_text.len() + 4)?.to_le_bytes());
    path.extend(file_text);
    path.extend(END_NODE);
    let mut data = Vec::new();
    data.extend(1u32.to_le_bytes());
    data.extend(u16::try_from(path.len())?.to_le_bytes());
    data.extend(utf16_bytes(description));
    data.extend(path);
    if preserve_optional {
        data.extend(option.optional_data);
    }
    Ok(Variable {
        attributes: 7,
        data,
    })
}

pub fn find_reference(
    fw: &impl Firmware,
    esp: Uuid,
    requested: Option<&str>,
) -> Result<(String, Variable, Variable)> {
    let order = fw
        .get("BootOrder")?
        .context("Firmware BootOrder is absent")?;
    let ordered = indices(&order)?;
    if let Some(name) = requested {
        let number = boot_number(name)?;
        ensure!(
            ordered.contains(&number),
            "Reference is absent from the normal boot order"
        );
        let name = format!("Boot{number:04X}");
        let variable = fw.get(&name)?.context("Reference boot option is absent")?;
        make_option(&variable, esp)?;
        return Ok((name, variable, order));
    }
    let mut found = Vec::new();
    for number in ordered {
        let name = format!("Boot{number:04X}");
        if let Some(variable) = fw.get(&name)?
            && make_option(&variable, esp).is_ok()
        {
            found.push((name, variable));
        }
    }
    ensure!(
        found.len() == 1,
        "Expected exactly one Windows option on this ESP; select --reference Boot#### explicitly"
    );
    let (name, variable) = found.remove(0);
    Ok((name, variable, order))
}

pub fn allocate(fw: &impl Firmware, order: &Variable) -> Result<u16> {
    allocate_excluding(fw, order, &[])
}

pub fn allocate_excluding(fw: &impl Firmware, order: &Variable, reserved: &[u16]) -> Result<u16> {
    let mut used: BTreeSet<_> = indices(order)?.into_iter().collect();
    used.extend(reserved);
    for number in 0..=u16::MAX {
        if !used.contains(&number) && fw.get(&format!("Boot{number:04X}"))?.is_none() {
            return Ok(number);
        }
    }
    bail!("Firmware boot-option namespace is full")
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub boot_order: Vec<u16>,
    pub boot_next: Option<u16>,
    pub boot_current: Option<u16>,
    pub options: Vec<OptionSummary>,
}

#[derive(Debug, Serialize)]
pub struct OptionSummary {
    pub name: String,
    pub description: String,
    pub file_path: Option<String>,
    pub partition_id: Option<Uuid>,
}

pub fn inspect(fw: &impl Firmware) -> Result<Snapshot> {
    let order = fw
        .get("BootOrder")?
        .context("Firmware BootOrder is absent")?;
    let order = indices(&order)?;
    let next = fw.get("BootNext")?.as_ref().map(index).transpose()?;
    let current = fw.get("BootCurrent")?.as_ref().map(index).transpose()?;
    let mut numbers: BTreeSet<_> = order.iter().copied().collect();
    numbers.extend(next);
    numbers.extend(current);
    let mut options = Vec::new();
    for number in numbers {
        let name = format!("Boot{number:04X}");
        if let Some(variable) = fw.get(&name)? {
            match LoadOption::parse(&variable.data) {
                Ok(option) => options.push(OptionSummary {
                    name,
                    description: option.description.clone(),
                    file_path: option.file_path().ok(),
                    partition_id: option.partition_id().ok(),
                }),
                Err(error) => options.push(OptionSummary {
                    name,
                    description: format!("Invalid option: {error}"),
                    file_path: None,
                    partition_id: None,
                }),
            }
        }
    }
    Ok(Snapshot {
        boot_order: order,
        boot_next: next,
        boot_current: current,
        options,
    })
}
