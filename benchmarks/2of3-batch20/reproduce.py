import subprocess, pathlib, tarfile, io, importlib.util, json
repo=pathlib.Path('/home/wenke/svarog-ecdsa-otmta')
root=pathlib.Path('/tmp/otmta-batch20');root.mkdir(exist_ok=True)
original=(repo/'scripts/bench_sign_setup.py').read_text()
original=original.replace('["2-of-2", "2-of-3", "3-of-3"]','["2-of-3"]').replace('for batch in [1, 4]:','for batch in [20]:')
(root/'runner.py').write_text(original)
spec=importlib.util.spec_from_file_location('runner',root/'runner.py');runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
bench=(repo/'src/timing_bench.rs').read_text().replace('[(2, 2), (3, 2), (3, 3)]','[(3, 2)]').replace('for batch in [1, 4]','for batch in [20]')
refs={};exes={}
for label,branch in [('baseline','main'),('inline','sign-heavy')]:
 ref=subprocess.check_output(['git','-C',str(repo),'rev-parse',branch],text=True).strip();refs[branch]=ref
 source=root/label
 with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['git','-C',str(repo),'archive',ref]))) as tar:tar.extractall(source,filter='data')
 (source/'src/timing_bench.rs').write_text(bench)
 lib=source/'src/lib.rs'
 if 'mod timing_bench;' not in lib.read_text():lib.write_text(lib.read_text()+'\n#[cfg(test)]\nmod timing_bench;\n')
 cargo=source/'Cargo.toml';cargo.write_text(cargo.read_text().replace('"macros", "time"]','"macros", "time", "sync"]'))
 exes[label]=runner.build(source,root/(label+'-target'))
output=root/'results';summary=runner.measure(exes,output,samples=10,blocks=4,warmup=3)
(output/'refs.json').write_text(json.dumps(refs,indent=2)+'\n')
print(json.dumps(summary,indent=2))
